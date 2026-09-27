package main

// ipbinding.go binds overlay IP addresses to node KEYS, and is the check every
// inbound path runs before it believes a peer's claim to an address.
//
// THE BUG THIS CLOSES
//
// A Noise session authenticates a peer's static key, but nothing tied that key
// to the overlay addresses the peer then used. An address announce ('A'), a
// keepalive carrying an address, the source address of a data packet, or the
// inner source of a relay frame were all taken at face value: any admitted
// node could claim ANY overlay IP, and this node would learn "that IP lives
// behind this session", record it as the key's address, and route the real
// owner's traffic to the claimant. WireGuard closes the same hole with
// AllowedIPs (cryptokey routing); this file is the equivalent.
//
// WHAT COUNTS AS OWNERSHIP — strongest first
//
//  1. An admin-signed provision for the address (the newest one for that
//     address). It decides outright: only the key it names owns the address.
//     This is the only binding that cannot be contested, and the recommended
//     one for any address that matters.
//  2. The node's primary derived address (deriveOverlayIP, salt 0). Anyone
//     can recompute it from the key.
//  3. A collision-hop address (salts 1..ipBindingMaxSalt). Also derived, but
//     one key covers many of these, so it proves little on its own.
//  4. An address set on the device itself (tun.address_cidr,
//     OVERLAY_ADDRESS, the desktop "overlay IP" box, first-run setup). Nothing
//     proves it.
//
// INCUMBENCY. The first key seen using an address over an authenticated
// channel (a Noise session or an end-to-end envelope) holds it, and other keys
// are refused while it does — unless their claim is STRONGER (a provision, or
// the address being their primary derived address), which displaces a weaker
// holder. A holder is released when its key is revoked, moves to another
// address, or has been silent for ipBindingIdleTTL. A claim of kind 3 or 4 is
// also refused outright for an address that a known key derives as its
// primary one. Bindings live in memory; a restarted node relearns them.
//
// So a live node can never have its address taken by a weaker claim, which is
// what stops an admitted insider from hijacking a running node's traffic.
// What first-come cannot prevent is a node claiming an address that nobody is
// using yet (for example one belonging to a device that is offline), or — for
// device-set addresses only — a relay naming itself as the owner of an
// address this node has not heard from directly (see OwnerOf). Admin
// provisioning closes both for the addresses you care about.
//
// IP_BINDING=strict additionally refuses kind 4 entirely (such devices must
// be assigned in the admin panel), and a node with such an address shows a
// warning on its dashboard. The default does not: in real fleets phones hop
// addresses and containers pin them, and refusing those broke connectivity.
//
// Addresses OUTSIDE the overlay subnet are never "owned" here; the only
// legitimate source of such packets is an exit node's return traffic, which
// sourceAllowedFrom handles separately.

import (
	"encoding/base64"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// ipBindingMaxSalt bounds how far along the collision-hop sequence an
	// address still counts as derived (kind 3). Hops advance up to 16 salts
	// per conflict event, and phones hop repeatedly; beyond this an address is
	// treated like a pinned one (kind 4).
	ipBindingMaxSalt = 128
	// ipBindingVerdictTTL caches ownership verdicts for the per-packet path.
	// Short, so a new provision or revocation takes effect within seconds.
	ipBindingVerdictTTL = 5 * time.Second
	// ipBindingIdleTTL is how long a binding survives its key being
	// silent. Deliberately long: expiry is what would let another key take the
	// address over, so it must never happen during ordinary sleep or roaming.
	ipBindingIdleTTL      = 24 * time.Hour
	ipBindingMaxDerived   = 4096
	ipBindingMaxVerdicts  = 16384
	ipBindingMaxBindings  = 4096
	ipBindingRejectLogGap = time.Minute
)

type ipBindingMode int

const (
	ipBindingDefault ipBindingMode = iota
	ipBindingStrict
)

func parseIPBindingMode(v string) ipBindingMode {
	if strings.EqualFold(strings.TrimSpace(v), "strict") {
		return ipBindingStrict
	}
	return ipBindingDefault
}

var ipBindingModeSetting = parseIPBindingMode(os.Getenv("IP_BINDING"))

// applyIPBindingConfig applies the config file's ip_binding setting unless the
// IP_BINDING environment variable already chose a mode.
func applyIPBindingConfig(v string) {
	if os.Getenv("IP_BINDING") == "" && strings.TrimSpace(v) != "" {
		ipBindingModeSetting = parseIPBindingMode(v)
	}
	if ipBindingStrictNow() {
		log.Printf("[ip-binding] strict: only derived or admin-assigned overlay addresses are accepted")
	} else {
		log.Printf("[ip-binding] default: admin-assigned and derived addresses win; other addresses are held first-come")
	}
}

// ipBindingStrictNow reports whether device-pinned address claims are refused.
func ipBindingStrictNow() bool { return ipBindingModeSetting == ipBindingStrict }

// Claim strengths (see the file comment).
const (
	claimPinned  = 1
	claimHopped  = 2
	claimPrimary = 3
)

type derivedKey struct {
	cidr string
	pub  [32]byte
}

type verdictKey struct {
	pub  [32]byte
	ip   string
	bind bool
}

type verdict struct {
	ok  bool
	exp time.Time
}

type tofuBinding struct {
	pub      [32]byte
	seen     time.Time
	strength int // claimPinned / claimHopped / claimPrimary
}

type ipBindingTable struct {
	mu       sync.RWMutex
	derived  map[derivedKey]map[string]int
	verdicts map[verdictKey]verdict

	tofuMu sync.Mutex
	tofu   map[string]*tofuBinding

	logMu   sync.Mutex
	lastLog map[verdictKey]time.Time
}

var ipBindings = newIPBindingTable()

func newIPBindingTable() *ipBindingTable {
	return &ipBindingTable{
		derived:  map[derivedKey]map[string]int{},
		verdicts: map[verdictKey]verdict{},
		tofu:     map[string]*tofuBinding{},
		lastLog:  map[verdictKey]time.Time{},
	}
}

// derivedSet maps every address pub can derive inside cidr (salts
// 0..ipBindingMaxSalt) to the lowest salt producing it; computed once per key.
func (t *ipBindingTable) derivedSet(cidr string, pub [32]byte) map[string]int {
	k := derivedKey{cidr, pub}
	t.mu.RLock()
	set, ok := t.derived[k]
	t.mu.RUnlock()
	if ok {
		return set
	}
	set = make(map[string]int, ipBindingMaxSalt+1)
	for salt := 0; salt <= ipBindingMaxSalt; salt++ {
		a, err := deriveOverlayIPSalted(cidr, pub, salt)
		if err != nil {
			break
		}
		if _, seen := set[stripMask(a)]; !seen {
			set[stripMask(a)] = salt
		}
	}
	t.mu.Lock()
	if len(t.derived) >= ipBindingMaxDerived {
		t.derived = map[derivedKey]map[string]int{}
	}
	t.derived[k] = set
	t.mu.Unlock()
	return set
}

// strength classifies pub's (non-provisioned) claim to ip.
func (t *ipBindingTable) strength(pub [32]byte, ip string) int {
	if overlayCIDR == "" {
		return claimPinned
	}
	salt, ok := t.derivedSet(overlayCIDR, pub)[ip]
	switch {
	case !ok:
		return claimPinned
	case salt == 0:
		return claimPrimary
	default:
		return claimHopped
	}
}

// derives reports whether ip is one of pub's derived addresses (any salt).
func (t *ipBindingTable) derives(cidr string, pub [32]byte, ip string) bool {
	if cidr == "" {
		return false
	}
	_, ok := t.derivedSet(cidr, pub)[ip]
	return ok
}

// provisionedOwners returns the key(s) holding the NEWEST live admin
// provision for ip. Older provisions for the same address are leftovers of
// reinstalls (provision.go retires them as newer ones arrive, but gossip can
// carry them back), and must not keep an address bound to a dead key.
func provisionedOwners(ip string) [][32]byte {
	if provisions == nil {
		return nil
	}
	var out [][32]byte
	var best int64
	for _, rec := range provisions.list() {
		if rec.Address == "" || stripMask(normalizeOverlayAddr(rec.Address)) != ip {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(rec.PubKey)
		if err != nil || len(raw) != 32 {
			continue
		}
		var pub [32]byte
		copy(pub[:], raw)
		if revocations != nil && revocations.isRevoked(pub) {
			continue
		}
		switch {
		case len(out) == 0 || rec.Seq > best:
			out, best = [][32]byte{pub}, rec.Seq
		case rec.Seq == best:
			out = append(out, pub)
		}
	}
	return out
}

func inOverlaySubnet(ip string) bool {
	n := overlayNet
	if n == nil {
		if overlayCIDR == "" {
			return false
		}
		var err error
		if _, n, err = net.ParseCIDR(overlayCIDR); err != nil {
			return false
		}
	}
	p := net.ParseIP(ip)
	return p != nil && n.Contains(p)
}

// provisioned reports whether an admin provision decides ip:
// (owner, true) when one does, (false, false) when none exists.
func provisioned(pub [32]byte, ip string) (owner, decided bool) {
	owners := provisionedOwners(ip)
	if len(owners) == 0 {
		return false, false
	}
	for _, o := range owners {
		if o == pub {
			return true, true
		}
	}
	return false, true
}

// owns is the uncached ownership decision. bind=true lets the claim create or
// refresh an incumbency binding; it must only be passed for claims that
// arrived over a channel authenticating pub (a Noise session or an end-to-end
// envelope). bind=false answers "may traffic for ip be handed to pub" without
// changing anything.
func (t *ipBindingTable) owns(pub [32]byte, ip string, bind bool) bool {
	if pub == ([32]byte{}) || !inOverlaySubnet(ip) {
		return false
	}
	if revocations != nil && revocations.isRevoked(pub) {
		return false
	}
	if owner, decided := provisioned(pub, ip); decided {
		if owner && bind {
			t.releaseOthers(pub, ip)
		}
		return owner
	}
	str := t.strength(pub, ip)
	if str == claimPinned && ipBindingStrictNow() {
		return false
	}
	if str < claimPrimary {
		// Never for an address a known key derives as its primary one.
		for _, k := range knownKeysClaiming(ip) {
			if k != pub && t.strength(k, ip) == claimPrimary {
				return false
			}
		}
	}
	// Our own address: only a genuine primary-derived collision may contest
	// it (the resolver then decides who moves), and it is never bound to
	// anyone else.
	if ip == e2eSelfIP() {
		return str == claimPrimary
	}

	now := time.Now()
	t.tofuMu.Lock()
	defer t.tofuMu.Unlock()
	b := t.tofu[ip]
	if b != nil && b.pub != pub {
		stale := now.Sub(b.seen) > ipBindingIdleTTL ||
			(revocations != nil && revocations.isRevoked(b.pub))
		switch {
		case stale:
			delete(t.tofu, ip)
			b = nil
		case str > b.strength:
			// A stronger claim beats a weaker holder — but only a claim the
			// key actually MAKES. Being able to derive an address is not a
			// claim: every key derives ~40% of a /24 through its collision-hop
			// salts, so without this a relay that merely could derive the
			// address was taken for its owner and handed traffic it can
			// only drop. The holder is displaced by an authenticated claim.
			if !bind {
				return claimsAddress(pub, ip)
			}
			delete(t.tofu, ip)
			b = nil
		default:
			return false // the incumbent keeps the address
		}
	}
	if !bind {
		// Nobody holds it yet: a primary derived address may be addressed
		// (first contact) if its key says it uses it; anything weaker only
		// once its key has claimed it here.
		return b != nil || (str == claimPrimary && claimsAddress(pub, ip))
	}
	if b == nil {
		if len(t.tofu) >= ipBindingMaxBindings {
			for k, v := range t.tofu {
				if now.Sub(v.seen) > ipBindingIdleTTL {
					delete(t.tofu, k)
				}
			}
			if len(t.tofu) >= ipBindingMaxBindings {
				return false
			}
		}
		// A node holds ONE overlay address. Claiming a new one (a collision
		// hop, a re-address) releases the old, so the address it left is free
		// for whoever legitimately stays on it.
		released := []string{ip}
		for other, ob := range t.tofu {
			if ob.pub == pub {
				delete(t.tofu, other)
				released = append(released, other)
			}
		}
		t.tofu[ip] = &tofuBinding{pub: pub, seen: now, strength: str}
		t.dropVerdicts(released)
		return true
	}
	if str > b.strength {
		b.strength = str
	}
	b.seen = now
	return true
}

// releaseOthers drops every binding pub holds except ip. Takes tofuMu.
func (t *ipBindingTable) releaseOthers(pub [32]byte, ip string) {
	t.tofuMu.Lock()
	defer t.tofuMu.Unlock()
	var released []string
	for other, ob := range t.tofu {
		if ob.pub == pub && other != ip {
			delete(t.tofu, other)
			released = append(released, other)
		}
	}
	if len(released) > 0 {
		t.dropVerdicts(released)
	}
}

// dropVerdicts forgets cached answers about the given addresses.
func (t *ipBindingTable) dropVerdicts(ips []string) {
	set := make(map[string]bool, len(ips))
	for _, ip := range ips {
		set[ip] = true
	}
	t.mu.Lock()
	for k := range t.verdicts {
		if set[k.ip] {
			delete(t.verdicts, k)
		}
	}
	t.mu.Unlock()
}

// knownKeysClaiming lists keys this node has heard associated with ip:
// verified self-claims (direct announces, authenticated relayed traffic) and
// roster gossip. Callers still verify each candidate.
func knownKeysClaiming(ip string) [][32]byte {
	var out [][32]byte
	nameMu.Lock()
	for k, v := range peerOverlayIPs {
		if v == ip {
			out = append(out, k)
		}
	}
	nameMu.Unlock()
	for _, e := range rosterSnapshot() {
		if e.IP != ip || e.PK == "" {
			continue
		}
		if raw, err := base64.StdEncoding.DecodeString(e.PK); err == nil && len(raw) == 32 {
			var k [32]byte
			copy(k[:], raw)
			out = append(out, k)
		}
	}
	return out
}

// claimsAddress reports whether pub has said it uses ip: in its own verified
// announces here, or in roster gossip.
func claimsAddress(pub [32]byte, ip string) bool {
	if peerOverlayIPByPub(pub) == ip {
		return true
	}
	for _, e := range rosterSnapshot() {
		if e.IP != ip || e.PK == "" {
			continue
		}
		if raw, err := base64.StdEncoding.DecodeString(e.PK); err == nil && len(raw) == 32 && [32]byte(raw) == pub {
			return true
		}
	}
	return false
}

// IsNodeAt reports whether the peer with key pub IS the node at overlay
// address ip — so a packet for ip may be handed to pub's session as is —
// rather than, at most, a relay toward it.
func (t *ipBindingTable) IsNodeAt(pub [32]byte, ip string) bool {
	return peerOverlayIPByPub(pub) == ip && t.OwnedBy(pub, ip, false)
}

// OwnedBy is the per-packet check: does pub own ip? Cached for
// ipBindingVerdictTTL, so a binding's liveness is refreshed at that cadence
// while its key keeps sending. bind has the same meaning as for owns.
func (t *ipBindingTable) OwnedBy(pub [32]byte, ip string, bind bool) bool {
	k := verdictKey{pub, ip, bind}
	now := time.Now()
	t.mu.RLock()
	v, ok := t.verdicts[k]
	t.mu.RUnlock()
	if ok && now.Before(v.exp) {
		return v.ok
	}
	res := t.owns(pub, ip, bind)
	t.mu.Lock()
	if len(t.verdicts) >= ipBindingMaxVerdicts {
		t.verdicts = map[verdictKey]verdict{}
	}
	t.verdicts[k] = verdict{ok: res, exp: now.Add(ipBindingVerdictTTL)}
	t.mu.Unlock()
	if !res && bind {
		t.noteRejected(pub, ip)
	}
	return res
}

func (t *ipBindingTable) noteRejected(pub [32]byte, ip string) {
	k := verdictKey{pub: pub, ip: ip}
	t.logMu.Lock()
	defer t.logMu.Unlock()
	if last, ok := t.lastLog[k]; ok && time.Since(last) < ipBindingRejectLogGap {
		return
	}
	if len(t.lastLog) > 4096 {
		t.lastLog = map[verdictKey]time.Time{}
	}
	t.lastLog[k] = time.Now()
	log.Printf("[ip-binding] REJECTED: key %s used overlay address %s, which it does not own "+
		"(another live node holds it, it is admin-assigned or derived to a different node, or IP_BINDING=strict "+
		"refuses device-set addresses). To give a device a specific address, assign it in the admin panel.", peerKeyFingerprint(pub[:]), ip)
}

// Forget drops pub's bindings and every cached verdict that involved it or
// the addresses it held (revocation, key rotation, tests).
func (t *ipBindingTable) Forget(pub [32]byte) {
	t.tofuMu.Lock()
	released := map[string]bool{}
	for ip, b := range t.tofu {
		if b.pub == pub {
			delete(t.tofu, ip)
			released[ip] = true
		}
	}
	t.tofuMu.Unlock()
	t.mu.Lock()
	for k := range t.verdicts {
		if k.pub == pub || released[k.ip] {
			delete(t.verdicts, k)
		}
	}
	t.mu.Unlock()
}

// OwnerOf resolves the key that owns ip, for sealing end-to-end traffic to
// it. Candidates come from admin provisions, direct sessions' verified
// addresses and roster gossip; only a candidate whose ownership is proven (or
// already tofu-bound) is returned, so a relay lying in the roster cannot
// redirect traffic to itself.
func (t *ipBindingTable) OwnerOf(ip string) ([32]byte, bool) {
	if owners := provisionedOwners(ip); len(owners) > 0 {
		// Prefer a live one if several (reinstall leftovers).
		for _, o := range owners {
			if claimantIsLive(o) {
				return o, true
			}
		}
		return owners[0], true
	}
	var cands [][32]byte
	if GlobalSessions != nil {
		for _, a := range GlobalSessions.EstablishedAddrs() {
			if s := GlobalSessions.GetByAddr(a); s != nil && peerOverlayIPByPub(s.peerStatic) == ip {
				cands = append(cands, s.peerStatic)
			}
		}
	}
	cands = append(cands, knownKeysClaiming(ip)...)
	// A candidate is used only if it already holds the address here or the
	// address is its primary derived one (and nobody stronger holds it). A
	// roster entry is a third party's word and never creates a binding:
	// otherwise a lying relay could name itself as the owner of traffic it
	// carries. The strongest acceptable candidate wins.
	var best [32]byte
	bestStr := 0
	distinct := map[[32]byte]bool{}
	for _, c := range cands {
		distinct[c] = true
		if !t.OwnedBy(c, ip, false) {
			continue
		}
		if st := t.strength(c, ip); st > bestStr {
			best, bestStr = c, st
		}
	}
	if bestStr > 0 {
		return best, true
	}
	// Default mode, first contact with a device-set address that only a
	// relay can reach: the roster (from the peer that holds a session to
	// it) is the only evidence there is. Use it when exactly one key claims
	// the address and nobody holds it here — without binding anything; the
	// node's own authenticated reply does that. This is the documented
	// weakness of device-set addresses: a relay could name itself.
	// IP_BINDING=strict never does this.
	if len(distinct) == 1 && !ipBindingStrictNow() {
		for c := range distinct {
			t.tofuMu.Lock()
			b := t.tofu[ip]
			t.tofuMu.Unlock()
			if b == nil && (revocations == nil || !revocations.isRevoked(c)) {
				if owner, decided := provisioned(c, ip); !decided || owner {
					return c, true
				}
			}
		}
	}
	return [32]byte{}, false
}

// sourceAllowedFrom decides whether a packet with source address src may be
// accepted from a peer authenticated as pub. Overlay sources must be owned by
// pub. Non-overlay sources are only legitimate as exit-node return traffic:
// this node must be using an exit and pub must be an exit it knows about.
func sourceAllowedFrom(pub [32]byte, src string) bool {
	if src == "" {
		return false
	}
	if inOverlaySubnet(src) {
		return ipBindings.OwnedBy(pub, src, true)
	}
	return usingExit() && isKnownExit(pub)
}

func isKnownExit(pub [32]byte) bool {
	exitMu.Lock()
	defer exitMu.Unlock()
	_, ok := exitCandidates[pub]
	return ok
}

// --- this node's own address -------------------------------------------------

const ipBindingSelfSource = "ip-binding"

var ipBindingSelfWarned bool

// checkSelfAddressVerifiable warns — in the log and on this node's dashboard
// — when peers will refuse this node's own address: strict mode, and the
// address is neither derived from this node's key nor assigned to it.
func checkSelfAddressVerifiable() {
	mine := e2eSelfIP()
	if mine == "" || gKP.pub == ([32]byte{}) {
		return
	}
	ok := !ipBindingStrictNow() || ipBindings.strength(gKP.pub, mine) > claimPinned
	if !ok {
		owner, decided := provisioned(gKP.pub, mine)
		ok = decided && owner
	}
	ipConflictMu.Lock()
	cur := ipConflictLast
	ipConflictMu.Unlock()
	mineRecord := cur != nil && cur.Source == ipBindingSelfSource
	if ok {
		if mineRecord {
			ipConflictMu.Lock()
			if ipConflictLast == cur {
				ipConflictLast = nil
			}
			ipConflictMu.Unlock()
		}
		ipBindingSelfWarned = false
		return
	}
	if cur != nil && !cur.Resolved && !mineRecord {
		return // a real collision is more urgent; don't overwrite it
	}
	fp := peerKeyFingerprint(gKP.pub[:])
	if !ipBindingSelfWarned {
		ipBindingSelfWarned = true
		log.Printf("[ip-binding] WARNING: this node's overlay address %s was set on this device only. "+
			"Other nodes refuse addresses they cannot verify, so traffic to and from this node will be dropped. "+
			"Assign %s to this device (key %s) in the admin panel, or clear the manual address to use the automatic one.",
			mine, mine, fp)
	}
	if mineRecord && !cur.Resolved && cur.OldIP == mine {
		return
	}
	setIPConflict(ipConflictRecord{
		OldIP: mine,
		Reason: "This device's overlay address " + mine + " was set on this device only, and other devices " +
			"refuse addresses they cannot verify — so traffic to and from it is dropped. Assign " + mine +
			" to this device in the admin panel, or clear the manual address to use the automatic one.",
		SelfFP: fp,
		Source: ipBindingSelfSource,
	})
}
