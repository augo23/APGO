package main

// ipclaim.go makes a JOINING node give up an overlay address that an existing
// member already holds, instead of sitting on the collision.
//
// The pre-existing self-healing (handleAddrConflict) only fires on evidence
// that arrives on a DIRECT session: an 'A' address announce or a keepalive
// carrying the sender's overlay IP. That covers "two nodes are already talking
// and discover they share an address", but it is exactly the wrong shape for
// the case that actually bites — a device joining a network that has admission
// control:
//
//   - the joining device derives its address from its key before it has met
//     anyone, so nothing has told it the address is taken;
//   - it is NOT approved yet, so its data plane is gated and the peers that
//     would have proved the collision may never reach the keepalive path;
//   - the approved node's claim is the one that must win — the mesh already
//     routes that address to it, and everything the operator did (approve,
//     provision, pin) points there.
//
// What DOES arrive early is control gossip: the roster ('T'), admin provisions
// ('V') and each peer's announced address. Every one of those is a statement
// that some other key holds an address. resolveOverlayIPCollision reads all
// three, decides whether this node or the other one should yield, and — when
// this node yields and its address was auto-derived — hops to the next free
// derived address live, then records the event so the joining device's own UI
// can show the new address and say why it changed.

import (
	"encoding/base64"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// ipClaim describes some OTHER node's claim on an overlay address.
type ipClaim struct {
	pub        [32]byte
	fp         string
	name       string
	source     string // "provision" | "roster" | "peer"
	provisoned bool   // holds an admin-signed provision for the address
	seq        int64  // that provision's signature sequence (0 = none)
	approved   bool   // admin-approved on this network
	// live reports whether this key is actually PRESENT — an established
	// session, or a fresh roster entry. A claim from a key that nothing has
	// heard from is a GHOST: the usual cause is a machine that was reinstalled
	// and came back with a new node key, leaving its old key's admin provision
	// behind. That case needs opposite advice from a real collision (reclaim
	// the address, don't move off it), so it has to be distinguishable here.
	live bool
}

// overlayIPClaims returns every OTHER node known to claim ip, from admin
// provisions, roster gossip and peers' own address announcements.
func overlayIPClaims(ip string) []ipClaim {
	ip = stripMask(strings.TrimSpace(ip))
	if ip == "" || net.ParseIP(ip) == nil {
		return nil
	}
	seen := map[[32]byte]int{} // pub -> index in out
	var out []ipClaim
	add := func(pub [32]byte, source string, provisioned bool, seq int64) {
		if pub == gKP.pub || pub == ([32]byte{}) {
			return
		}
		// A revoked key's claim is not a claim. Revocation is the operator
		// saying this device is gone; continuing to defend its address would
		// strand a live node behind a record of a dead one.
		if revocations != nil && revocations.isRevoked(pub) {
			return
		}
		if i, ok := seen[pub]; ok {
			out[i].provisoned = out[i].provisoned || provisioned
			if seq > out[i].seq {
				out[i].seq = seq
			}
			out[i].live = out[i].live || claimantIsLive(pub)
			return
		}
		seen[pub] = len(out)
		out = append(out, ipClaim{
			pub:        pub,
			fp:         peerKeyFingerprint(pub[:]),
			name:       resolvePeerName(pub),
			source:     source,
			provisoned: provisioned,
			seq:        seq,
			approved:   approvals.isApproved(pub),
			live:       claimantIsLive(pub),
		})
	}

	// 1. Admin provisions — the strongest claim there is: an operator typed it.
	for _, rec := range provisions.list() {
		if rec.Address == "" {
			continue
		}
		if stripMask(normalizeOverlayAddr(rec.Address)) != ip {
			continue
		}
		if raw, err := base64.StdEncoding.DecodeString(rec.PubKey); err == nil && len(raw) == 32 {
			var pub [32]byte
			copy(pub[:], raw)
			add(pub, "provision", true, rec.Seq)
		}
	}
	// 2. Roster gossip — reaches a joining node in one hop, including for
	//    members it has no direct session to.
	for _, e := range rosterSnapshot() {
		if e.IP != ip || e.PK == "" {
			continue
		}
		if raw, err := base64.StdEncoding.DecodeString(e.PK); err == nil && len(raw) == 32 {
			var pub [32]byte
			copy(pub[:], raw)
			add(pub, "roster", false, 0)
		}
	}
	// 3. Direct peers' own announced addresses.
	nameMu.Lock()
	for pub, pip := range peerOverlayIPs {
		if stripMask(pip) == ip {
			p := pub
			nameMu.Unlock()
			add(p, "peer", false, 0)
			nameMu.Lock()
		}
	}
	nameMu.Unlock()
	return out
}

// claimantIsLive reports whether anything has actually HEARD from this key:
// an established session, or a roster entry inside its TTL. False means the key
// exists only in stored records — the signature of an install that is gone.
func claimantIsLive(pub [32]byte) bool {
	if GlobalSessions != nil {
		for _, addr := range GlobalSessions.EstablishedAddrs() {
			if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() && s.peerStatic == pub {
				return true
			}
		}
	}
	return rosterIPByKey(pub) != ""
}

// selfProvisionSeq returns the sequence of THIS node's admin provision for ip,
// or 0 if the operator has not assigned us that address.
func selfProvisionSeq(ip string) int64 {
	rec, ok := provisions.get(gKP.pub)
	if !ok || rec.Address == "" {
		return 0
	}
	if stripMask(normalizeOverlayAddr(rec.Address)) != stripMask(ip) {
		return 0
	}
	return rec.Seq
}

// yieldsTo reports whether THIS node should give up the address to c.
//
// The order matters, and it is deliberately biased toward whoever was here
// first, because the alternative — both sides hopping — churns addresses on a
// live network to spare a device that has not carried a packet yet.
//
//  1. An admin provision always wins. The operator assigned that address.
//  2. An approved member beats an unapproved one. This is the joining case:
//     the newcomer is pending, the incumbent is admitted, the newcomer moves.
//  3. Otherwise (same standing on both sides) break the tie deterministically
//     on the public key, so exactly ONE of the two moves and both agree which.
func yieldsTo(c ipClaim) bool {
	if c.provisoned {
		// Two admin provisions for one address: the NEWEST signature wins.
		// This is the same rule provStore.put and pruneSupersededAddresses
		// already apply, and it must be applied here too — otherwise a
		// reinstalled machine that an admin has correctly re-provisioned onto
		// its NEW key still reads the old key's leftover record as an
		// authority and offers to move off the address it was just given.
		if mine := selfProvisionSeq(myOverlayIP()); mine > 0 && mine >= c.seq {
			return false
		}
		return true
	}
	self := selfApproved()
	if c.approved != self {
		return c.approved // they're approved and we're not → we move
	}
	return strings.Compare(
		base64.StdEncoding.EncodeToString(gKP.pub[:]),
		base64.StdEncoding.EncodeToString(c.pub[:]),
	) > 0
}

// --- the conflict record shown in the UI ----------------------------------

// ipConflictRecord is the last overlay-address collision this node resolved (or
// failed to resolve), surfaced on /api/info as "ip_conflict" so the dashboard
// of the device that moved can display its NEW address and say why it changed.
type ipConflictRecord struct {
	OldIP    string `json:"old_ip"`
	NewIP    string `json:"new_ip"`  // "" when the address could not be changed
	PeerFP   string `json:"peer_fp"` // the node that keeps the address
	PeerName string `json:"peer_name,omitempty"`
	Reason   string `json:"reason"`   // human-readable, shown verbatim in the UI
	Resolved bool   `json:"resolved"` // false = still colliding, needs an operator
	// Stale marks the reinstall case: the claim comes from a key nothing has
	// heard from, so the fix is to RECLAIM the address onto this device's
	// current key rather than to move this device off it. SelfFP is that key,
	// which is what an admin has to select in the panel.
	Stale  bool   `json:"stale"`
	SelfFP string `json:"self_fp"`
	Source string `json:"source"` // where the claim came from
	AtUnix int64  `json:"at_unix"`
}

var (
	ipConflictMu   sync.Mutex
	ipConflictLast *ipConflictRecord
)

func setIPConflict(rec ipConflictRecord) {
	rec.AtUnix = time.Now().Unix()
	ipConflictMu.Lock()
	ipConflictLast = &rec
	ipConflictMu.Unlock()
}

// getIPConflict returns the last conflict record, or nil. Resolved records age
// out after an hour so a dashboard left open doesn't display a stale banner
// forever; unresolved ones stay until they are actually fixed.
func getIPConflict() *ipConflictRecord {
	ipConflictMu.Lock()
	defer ipConflictMu.Unlock()
	if ipConflictLast == nil {
		return nil
	}
	if ipConflictLast.Resolved && time.Since(time.Unix(ipConflictLast.AtUnix, 0)) > time.Hour {
		return nil
	}
	c := *ipConflictLast
	return &c
}

// clearIPConflictIfSettled drops an UNRESOLVED record once nobody else claims
// our address any more (the other node moved, or its provision was reissued).
func clearIPConflictIfSettled() {
	ipConflictMu.Lock()
	stale := ipConflictLast != nil && !ipConflictLast.Resolved
	ipConflictMu.Unlock()
	if !stale {
		return
	}
	if len(overlayIPClaims(myOverlayIP())) == 0 {
		ipConflictMu.Lock()
		ipConflictLast = nil
		ipConflictMu.Unlock()
	}
}

// --- the resolver ----------------------------------------------------------

var lastCollisionCheck struct {
	sync.Mutex
	at time.Time
}

// resolveOverlayIPCollision checks whether another node claims this node's
// overlay address and, if this node is the one that should yield, moves it to
// the next free derived address live.
//
// Safe to call from any gossip path: it is cheap, rate-limited, and a no-op on
// the overwhelmingly common case of no claimants.
func resolveOverlayIPCollision(trigger string) {
	mine := myOverlayIP()
	if mine == "" || gKP.pub == ([32]byte{}) {
		return
	}
	// Judging a claim requires knowing whether the claimant is LIVE, and that
	// question is meaningless before this node has joined anything: with no
	// sessions every key looks dead, so a real collision would read as a stale
	// record and a stale record would read the same. Wait for at least one
	// established session; the keepalive tick re-runs this within seconds.
	if !haveEstablishedSession() {
		return
	}
	claims := overlayIPClaims(mine)
	if len(claims) == 0 {
		clearIPConflictIfSettled()
		return
	}
	// Pick the strongest claim: a provision beats an approval beats the rest.
	best := claims[0]
	for _, c := range claims[1:] {
		if (c.provisoned && !best.provisoned) || (c.approved && !best.approved && !best.provisoned) {
			best = c
		}
	}
	if !yieldsTo(best) {
		// We keep the address. Say so once a minute; the other side is running
		// this same logic and should be moving.
		warnOnDuplicateOverlayClaim()
		return
	}

	lastCollisionCheck.Lock()
	if time.Since(lastCollisionCheck.at) < 15*time.Second {
		lastCollisionCheck.Unlock()
		return
	}
	lastCollisionCheck.at = time.Now()
	lastCollisionCheck.Unlock()

	who := best.fp
	if best.name != "" {
		who = best.name + " (" + best.fp + ")"
	}
	selfFP := peerKeyFingerprint(gKP.pub[:])
	if !best.live {
		// GHOST CLAIM. Nothing has heard from the claiming key — no session, no
		// roster entry — so there is no second device to collide with. This is
		// what a REINSTALL looks like from the inside: the machine came back
		// with a new node key, and the old key's admin provision for the
		// address outlived the install that earned it.
		//
		// Moving off the address here would be exactly wrong: it would abandon
		// a working, operator-chosen address to a record of a machine that no
		// longer exists. The fix is to re-provision the address onto THIS
		// device's current key, which supersedes the old claim everywhere
		// (newest signature wins).
		same := best.name != "" && best.name == getMyFriendlyName()
		log.Printf("[conflict] overlay address %s is claimed by %s, but nothing has heard from "+
			"that key (no session, no roster entry) — it is a stale claim, most likely from an "+
			"earlier install of this machine. Re-provision %s onto this device's key %s in the "+
			"admin panel to clear it.", mine, who, mine, selfFP)
		reason := "Overlay address " + mine + " is still claimed by an older node key, " + who +
			", that nothing on the network has heard from"
		if same {
			reason += " — it has this device's own name, so it is almost certainly this machine " +
				"before it was reinstalled"
		}
		reason += ". Nothing is actually using the address; the leftover record just needs to be " +
			"superseded. In the admin panel, assign " + mine + " to this device's CURRENT key (" +
			selfFP + ") — that replaces the old claim across the network."
		setIPConflict(ipConflictRecord{
			OldIP: mine, PeerFP: best.fp, PeerName: best.name, Resolved: false,
			Stale: true, SelfFP: selfFP, Source: best.source, Reason: reason,
		})
		return
	}
	if !addrAutoDerived {
		// Pinned or admin-assigned, and the other node is genuinely live:
		// hopping would undo an operator's decision, so this one is theirs.
		log.Printf("[conflict] overlay address %s is already held by live node %s, but this "+
			"node's address was assigned/pinned — not moving. Re-provision one of the two.",
			mine, who)
		setIPConflict(ipConflictRecord{
			OldIP: mine, PeerFP: best.fp, PeerName: best.name, Resolved: false,
			SelfFP: selfFP, Source: best.source,
			Reason: "This device's overlay address " + mine + " is also in use by " + who +
				", which is live on the network right now. This device's address was assigned by " +
				"an admin (or pinned in config), so it was not changed automatically — in the " +
				"admin panel, give one of the two devices a different address.",
		})
		return
	}
	if newCIDR, ok := nextFreeDerivedAddress(); ok {
		log.Printf("[conflict] overlay address %s is already in use by %s (%s) — moving this "+
			"node to %s automatically [trigger=%s]", mine, who, best.source, newCIDR, trigger)
		applyAddressLive(newCIDR)
		setIPConflict(ipConflictRecord{
			OldIP: mine, NewIP: stripMask(newCIDR), PeerFP: best.fp, PeerName: best.name,
			Resolved: true, SelfFP: selfFP, Source: best.source,
			Reason: "Overlay address " + mine + " was already in use by " + who +
				", so this device automatically moved to " + stripMask(newCIDR) + ".",
		})
		return
	}
	log.Printf("[conflict] overlay address %s is already in use by %s and no free derived "+
		"alternative was found — assign this node an address in the admin panel.", mine, who)
	setIPConflict(ipConflictRecord{
		OldIP: mine, PeerFP: best.fp, PeerName: best.name, Resolved: false,
		SelfFP: selfFP, Source: best.source,
		Reason: "This device's overlay address " + mine + " is already in use by " + who +
			", and no free alternative could be derived. Assign this device an address in the admin panel.",
	})
}

// nextFreeDerivedAddress walks the salted derivation sequence for the next
// address that nothing else claims, and returns it in CIDR form.
func nextFreeDerivedAddress() (string, bool) {
	addrConflictMu.Lock()
	defer addrConflictMu.Unlock()
	for i := 0; i < 16; i++ {
		addrHopSalt++
		cand, err := deriveOverlayIPSalted(overlayCIDR, gKP.pub, addrHopSalt)
		if err != nil {
			return "", false
		}
		candIP := stripMask(cand)
		if candIP == myOverlayIP() {
			continue
		}
		if len(overlayIPClaims(candIP)) > 0 {
			continue
		}
		if ipLearning != nil && ipLearning.Lookup(candIP) != nil {
			continue
		}
		lastAddrHop = time.Now()
		return cand, true
	}
	return "", false
}

// haveEstablishedSession reports whether this node holds at least one
// established session — i.e. it is actually on the network.
func haveEstablishedSession() bool {
	if GlobalSessions == nil {
		return false
	}
	for _, addr := range GlobalSessions.EstablishedAddrs() {
		if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
			return true
		}
	}
	return false
}
