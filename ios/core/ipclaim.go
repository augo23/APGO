package overlaymobile

// ipclaim.go is the mobile port of client/ipclaim.go: it makes a JOINING device
// give up an overlay address that an existing member already holds.
//
// The logic — where claims come from, who yields, and how a stale claim from a
// reinstalled machine is told apart from a real collision — is identical to the
// desktop copy, and the two MUST stay in step: both sides of a collision run
// this independently and have to reach opposite conclusions, so a phone that
// disagreed with a laptop about who moves would produce either a fight (both
// hop) or a standoff (neither does).
//
// ONE THING DIFFERS, and it is forced by the platform: the phone cannot
// re-address a live tunnel. iOS hands the extension a configured
// NEPacketTunnelProvider fd and Android a VpnService fd; the address is set by
// the app when it builds the tunnel, and the Go core is a guest inside it. So
// where the desktop calls applyAddressLive and keeps running, this stages the
// new address as a PENDING address and lets the app adopt it — which both apps
// already do on their poll loop (ContentView.adoptPendingAddressIfAny on iOS,
// the pendingAddress() branch in MainActivity.kt on Android): they write the
// address into the stored profile and re-establish the tunnel on it. The move
// therefore costs a reconnect on a phone and nothing on a desktop.

import (
	"encoding/base64"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// addrAutoDerived marks that this device's overlay address was derived from its
// key rather than chosen by the person (the app's octet field) or assigned by an
// admin. Only a derived address may be moved automatically; anything the user or
// operator typed is theirs to change.
var (
	addrAutoDerived bool
	addrHopMu       sync.Mutex
	addrHopSalt     int
	lastAddrHop     time.Time
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
	live       bool   // an established session or a fresh roster entry
}

// overlayIPClaims returns every OTHER node known to claim ip, from admin
// provisions, roster gossip and peers' own address announcements.
func overlayIPClaims(ip string) []ipClaim {
	ip = stripMask(strings.TrimSpace(ip))
	if ip == "" || net.ParseIP(ip) == nil {
		return nil
	}
	seen := map[[32]byte]int{}
	var out []ipClaim
	add := func(pub [32]byte, source string, provisioned bool, seq int64) {
		if pub == gKP.pub || pub == ([32]byte{}) {
			return
		}
		// A revoked key's claim is not a claim: revocation is the operator
		// saying the device is gone.
		if revocations != nil && revocations.isRevoked(pub) {
			return
		}
		if i, ok := seen[pub]; ok {
			out[i].provisoned = out[i].provisoned || provisioned
			if seq > out[i].seq {
				out[i].seq = seq
			}
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

	for _, rec := range provisions.list() {
		if rec.Address == "" || stripMask(normalizeOverlayAddr(rec.Address)) != ip {
			continue
		}
		if raw, err := base64.StdEncoding.DecodeString(rec.PubKey); err == nil && len(raw) == 32 {
			var pub [32]byte
			copy(pub[:], raw)
			add(pub, "provision", true, rec.Seq)
		}
	}
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
	nameMu.Lock()
	claimers := make([][32]byte, 0, 2)
	for pub, pip := range peerOverlayIPs {
		if stripMask(pip) == ip {
			claimers = append(claimers, pub)
		}
	}
	nameMu.Unlock()
	for _, pub := range claimers {
		add(pub, "peer", false, 0)
	}
	return out
}

// claimantIsLive reports whether anything has actually HEARD from this key: an
// established session, or a roster entry inside its TTL. False means the key
// exists only in stored records — the signature of an install that is gone.
func claimantIsLive(pub [32]byte) bool {
	if GlobalSessions != nil {
		for _, addr := range GlobalSessions.EstablishedAddrs() {
			if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() && s.peerStatic == pub {
				return true
			}
		}
	}
	fp := peerKeyFingerprint(pub[:])
	pk := base64.StdEncoding.EncodeToString(pub[:])
	for _, e := range rosterSnapshot() {
		if (e.PK != "" && e.PK == pk) || (e.FP != "" && e.FP == fp) {
			return true
		}
	}
	return false
}

// selfProvisionSeq returns the sequence of THIS device's admin provision for
// ip, or 0 if the operator has not assigned us that address.
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

// yieldsTo reports whether THIS device should give up the address to c.
// Identical ordering to client/ipclaim.go — see the note at the top of the file
// about why the two copies must agree.
func yieldsTo(c ipClaim) bool {
	if c.provisoned {
		if mine := selfProvisionSeq(myOverlayIP); mine > 0 && mine >= c.seq {
			return false // our provision is the newer signature
		}
		return true
	}
	self := selfApproved()
	if c.approved != self {
		return c.approved
	}
	return strings.Compare(
		base64.StdEncoding.EncodeToString(gKP.pub[:]),
		base64.StdEncoding.EncodeToString(c.pub[:]),
	) > 0
}

// --- the conflict record shown in the phone UI -----------------------------

type ipConflictRecord struct {
	OldIP    string `json:"old_ip"`
	NewIP    string `json:"new_ip"`
	PeerFP   string `json:"peer_fp"`
	PeerName string `json:"peer_name,omitempty"`
	Reason   string `json:"reason"`
	Resolved bool   `json:"resolved"`
	Stale    bool   `json:"stale"`
	SelfFP   string `json:"self_fp"`
	Source   string `json:"source"`
	AtUnix   int64  `json:"at_unix"`
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
// out after an hour; unresolved ones stay until they are actually fixed.
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

func clearIPConflictIfSettled() {
	ipConflictMu.Lock()
	stale := ipConflictLast != nil && !ipConflictLast.Resolved
	ipConflictMu.Unlock()
	if !stale {
		return
	}
	if len(overlayIPClaims(myOverlayIP)) == 0 {
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

// resolveOverlayIPCollision checks whether another node claims this device's
// overlay address and, if this device is the one that should yield, stages a
// free derived address for the app to adopt.
func resolveOverlayIPCollision(trigger string) {
	mine := myOverlayIP
	if mine == "" || gKP.pub == ([32]byte{}) {
		return
	}
	// Liveness is meaningless before this device has joined anything: with no
	// sessions every key looks dead, so a real collision would read as a stale
	// record. Wait for one established session; the keepalive tick re-runs it.
	if !haveEstablishedSession() {
		return
	}
	claims := overlayIPClaims(mine)
	if len(claims) == 0 {
		clearIPConflictIfSettled()
		return
	}
	best := claims[0]
	for _, c := range claims[1:] {
		if (c.provisoned && !best.provisoned) || (c.approved && !best.approved && !best.provisoned) {
			best = c
		}
	}
	if !yieldsTo(best) {
		return // we keep the address; the other side moves
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
		// A claim from a key nothing has heard from is a leftover record, not a
		// collision — most often this device before it was reinstalled or
		// reset, which on a phone is as easy as deleting and re-adding the app.
		// Reconnecting onto a different address would be the wrong move.
		same := best.name != "" && best.name == getMyFriendlyName()
		log.Printf("[conflict] overlay address %s is claimed by %s, but nothing has heard from "+
			"that key — stale claim, not a live collision. Re-provision %s onto this device's "+
			"key %s in the admin panel to clear it. [trigger=%s]", mine, who, mine, selfFP, trigger)
		reason := "Overlay address " + mine + " is still claimed by an older node key, " + who +
			", that nothing on the network has heard from"
		if same {
			reason += " — it carries this device's own name, so it is almost certainly this " +
				"device before it was reinstalled"
		}
		reason += ". Nothing is using the address. In the admin panel, assign " + mine +
			" to this device's CURRENT key (" + selfFP + ") to replace the old claim."
		setIPConflict(ipConflictRecord{
			OldIP: mine, PeerFP: best.fp, PeerName: best.name, Resolved: false,
			Stale: true, SelfFP: selfFP, Source: best.source, Reason: reason,
		})
		return
	}
	if !addrAutoDerived {
		// The address was typed by the person (the octet field) or assigned by
		// an admin. Reconnecting a phone onto a different address behind the
		// person's back is not a repair, so say what is wrong and stop.
		log.Printf("[conflict] overlay address %s is already held by live node %s, but this "+
			"device's address was chosen explicitly — not moving.", mine, who)
		setIPConflict(ipConflictRecord{
			OldIP: mine, PeerFP: best.fp, PeerName: best.name, Resolved: false,
			SelfFP: selfFP, Source: best.source,
			Reason: "This device's overlay address " + mine + " is also in use by " + who +
				", which is live on the network right now. This address was set explicitly " +
				"(or assigned by an admin), so it was not changed automatically — pick a " +
				"different address for one of the two devices.",
		})
		return
	}
	newCIDR, ok := nextFreeDerivedAddress()
	if !ok {
		log.Printf("[conflict] overlay address %s is in use by %s and no free derived "+
			"alternative was found.", mine, who)
		setIPConflict(ipConflictRecord{
			OldIP: mine, PeerFP: best.fp, PeerName: best.name, Resolved: false,
			SelfFP: selfFP, Source: best.source,
			Reason: "This device's overlay address " + mine + " is already in use by " + who +
				", and no free alternative could be derived. Set an address for this device manually.",
		})
		return
	}
	// Stage it and let the app re-establish the tunnel on the new address. The
	// record is written BEFORE the app is told, so the banner is already true
	// by the time the reconnect lands.
	log.Printf("[conflict] overlay address %s is already in use by %s (%s) — moving this "+
		"device to %s; the app will reconnect on the new address [trigger=%s]",
		mine, who, best.source, newCIDR, trigger)
	setIPConflict(ipConflictRecord{
		OldIP: mine, NewIP: stripMask(newCIDR), PeerFP: best.fp, PeerName: best.name,
		Resolved: true, SelfFP: selfFP, Source: best.source,
		Reason: "Overlay address " + mine + " was already in use by " + who +
			", so this device moved to " + stripMask(newCIDR) + " and reconnected.",
	})
	pendingAddrMu.Lock()
	pendingAddress = newCIDR
	pendingAddrMu.Unlock()
	if onPendingAddress != nil {
		go onPendingAddress(newCIDR)
	}
}

// nextFreeDerivedAddress walks the salted derivation sequence for the next
// address nothing else claims, and returns it in CIDR form.
func nextFreeDerivedAddress() (string, bool) {
	addrHopMu.Lock()
	defer addrHopMu.Unlock()
	if time.Since(lastAddrHop) < 30*time.Second {
		return "", false // a move is already in flight — let the app reconnect
	}
	for i := 0; i < 16; i++ {
		addrHopSalt++
		cand, err := deriveOverlayIPSalted(overlayCIDR, gKP.pub, addrHopSalt)
		if err != nil {
			return "", false
		}
		candIP := stripMask(cand)
		if candIP == myOverlayIP {
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

// haveEstablishedSession reports whether this device holds at least one
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
