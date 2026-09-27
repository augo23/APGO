package main

import (
	"encoding/base64"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDerivedAddressOwnership(t *testing.T) {
	self, a, b := testKeypair(t), testKeypair(t), testKeypair(t)
	testNode(t, self, nil)
	aIP := testDerivedIP(t, a.pub)
	if !ipBindings.OwnedBy(a.pub, aIP, true) {
		t.Fatal("a key must own its derived address")
	}
	if ipBindings.OwnedBy(b.pub, aIP, true) {
		t.Fatal("another key must not own a derived address, even on first use")
	}
	// Collision-hop addresses are also the key's.
	hop, _ := deriveOverlayIPSalted(overlayCIDR, a.pub, 5)
	if !ipBindings.OwnedBy(a.pub, stripMask(hop), true) {
		t.Fatal("a salted (collision-hop) address must be accepted when its node claims it")
	}
	// Outside the overlay: never owned.
	if ipBindings.OwnedBy(a.pub, "8.8.8.8", true) {
		t.Fatal("an internet address cannot be owned")
	}
}

func TestProvisionOverridesDerivation(t *testing.T) {
	self, a, b := testKeypair(t), testKeypair(t), testKeypair(t)
	testNode(t, self, nil)
	aIP := testDerivedIP(t, a.pub)
	provisions.mu.Lock()
	provisions.recs[b.pub] = SignedProvision{PubKey: base64.StdEncoding.EncodeToString(b.pub[:]), Address: aIP + "/24", Seq: 1}
	provisions.mu.Unlock()
	if !ipBindings.OwnedBy(b.pub, aIP, true) {
		t.Fatal("the provisioned key must own the address")
	}
	if ipBindings.OwnedBy(a.pub, aIP, true) {
		t.Fatal("a derived claim must lose to an admin provision for another key")
	}
	if k, ok := ipBindings.OwnerOf(aIP); !ok || k != b.pub {
		t.Fatal("OwnerOf must return the provisioned key")
	}
}

func TestTOFUBindingForPinnedAddresses(t *testing.T) {
	self, a, b := testKeypair(t), testKeypair(t), testKeypair(t)
	testNode(t, self, nil)
	ipBindingModeSetting = ipBindingDefault
	pinned := "10.22.99.200"
	for _, k := range [][32]byte{a.pub, b.pub} {
		if testDerivedIP(t, k) == pinned {
			t.Skip("random key happened to derive the pinned address")
		}
	}
	if ipBindings.OwnedBy(a.pub, pinned, false) {
		t.Fatal("a lookup without authentication must not create a binding")
	}
	if !ipBindings.OwnedBy(a.pub, pinned, true) {
		t.Fatal("first authenticated claim should bind in the default mode")
	}
	if !ipBindings.OwnedBy(a.pub, pinned, false) {
		t.Fatal("binding should be visible to lookups immediately")
	}
	if ipBindings.OwnedBy(b.pub, pinned, true) {
		t.Fatal("a second key must not take a bound address")
	}
	// Our own address is never tofu-bound to someone else.
	if ipBindings.OwnedBy(b.pub, myOverlayIP(), true) {
		t.Fatal("our own address was bound to another key")
	}
	// Revocation releases the binding.
	ipBindings.Forget(a.pub)
	if !ipBindings.OwnedBy(b.pub, pinned, true) {
		t.Fatal("binding not released after Forget")
	}
}

func TestStrictModeRejectsUnprovable(t *testing.T) {
	self, a := testKeypair(t), testKeypair(t)
	testNode(t, self, nil)
	ipBindingModeSetting = ipBindingStrict
	pinned := "10.22.99.201"
	if testDerivedIP(t, a.pub) == pinned {
		t.Skip("random key derived the pinned address")
	}
	if ipBindings.OwnedBy(a.pub, pinned, true) {
		t.Fatal("strict mode accepted an unprovable address")
	}
	if !ipBindings.OwnedBy(a.pub, testDerivedIP(t, a.pub), true) {
		t.Fatal("strict mode must still accept derived addresses")
	}
}

func TestSourceAllowedFromExitOnly(t *testing.T) {
	self, a, exit := testKeypair(t), testKeypair(t), testKeypair(t)
	testNode(t, self, nil)
	useExitFlag.Store(true)
	exitMu.Lock()
	old := exitCandidates
	exitCandidates = map[[32]byte]*exitInfo{exit.pub: {addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, lastReply: time.Now()}}
	exitMu.Unlock()
	t.Cleanup(func() { exitMu.Lock(); exitCandidates = old; exitMu.Unlock() })

	if sourceAllowedFrom(a.pub, "1.1.1.1") {
		t.Fatal("a non-exit peer may not send internet-sourced packets")
	}
	if !sourceAllowedFrom(exit.pub, "1.1.1.1") {
		t.Fatal("the exit's return traffic must be accepted")
	}
	if sourceAllowedFrom(exit.pub, testDerivedIP(t, a.pub)) {
		t.Fatal("an exit may not forge another node's overlay address")
	}
	useExitFlag.Store(false)
	if sourceAllowedFrom(exit.pub, "1.1.1.1") {
		t.Fatal("internet-sourced packets accepted while not using an exit")
	}
}

// Ingress: announces, keepalives and data from a key that does not own the
// address are ignored and never create a route.
func TestIngressRejectsForeignAddressClaims(t *testing.T) {
	self, m, victim := testKeypair(t), testKeypair(t), testKeypair(t)
	testNode(t, self, nil)
	mAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40100}
	GlobalSessions.set(mAddr, testPeerSession(t, gKP, m, mAddr))
	victimIP := testDerivedIP(t, victim.pub)

	handleControl(append([]byte{'A'}, []byte(victimIP)...), mAddr)
	if ipLearning.Lookup(victimIP) != nil {
		t.Fatal("forged address announce created a route")
	}
	if peerOverlayIPByPub(m.pub) == victimIP {
		t.Fatal("forged announce recorded as the key's address")
	}
	// Our own address, claimed without proof, must not trigger a hop.
	before := myOverlayIP()
	handleControl(append([]byte{'A'}, []byte(before)...), mAddr)
	if myOverlayIP() != before {
		t.Fatal("unprovable claim to our address changed it")
	}
	// A genuine announce is accepted.
	mIP := testDerivedIP(t, m.pub)
	handleControl(append([]byte{'A'}, []byte(mIP)...), mAddr)
	if l := ipLearning.Lookup(mIP); l == nil || l.String() != mAddr.String() {
		t.Fatal("genuine announce not learned")
	}
}

// A key that moves to a new address (collision hop) releases the old one, so
// the node that legitimately stays there is not locked out.
func TestHopReleasesOldAddress(t *testing.T) {
	self, a, b := testKeypair(t), testKeypair(t), testKeypair(t)
	testNode(t, self, nil)
	ipBindingModeSetting = ipBindingDefault // lets two keys "share" an address in the test
	shared := "10.22.99.50"
	next := "10.22.99.51"
	if !ipBindings.OwnedBy(a.pub, shared, true) {
		t.Fatal("setup: a should bind")
	}
	if ipBindings.OwnedBy(b.pub, shared, true) {
		t.Fatal("b must be refused while a holds the address")
	}
	if !ipBindings.OwnedBy(a.pub, next, true) {
		t.Fatal("a should be able to move")
	}
	if !ipBindings.OwnedBy(b.pub, shared, true) {
		t.Fatal("the address a left must be free for b")
	}
}

func TestModeParsing(t *testing.T) {
	if parseIPBindingMode("") != ipBindingDefault || parseIPBindingMode("tofu") != ipBindingDefault ||
		parseIPBindingMode("auto") != ipBindingDefault || parseIPBindingMode(" STRICT ") != ipBindingStrict {
		t.Fatal("mode parsing")
	}
}

func TestClaimPrecedence(t *testing.T) {
	self, a, owner := testKeypair(t), testKeypair(t), testKeypair(t)
	testNode(t, self, nil)
	ipBindingModeSetting = ipBindingDefault
	ownerIP := testDerivedIP(t, owner.pub)

	// A pinned claim to an address a known key derives as primary is refused.
	rosterMu.Lock()
	rosterNodes[ownerIP] = rosterView{rosterEntry: rosterEntry{IP: ownerIP, PK: base64.StdEncoding.EncodeToString(owner.pub[:])}, Seen: time.Now()}
	rosterMu.Unlock()
	if ipBindings.OwnedBy(a.pub, ownerIP, true) {
		t.Fatal("pinned claim over a known key's derived address accepted")
	}
	rosterMu.Lock()
	rosterNodes = map[string]rosterView{}
	rosterMu.Unlock()
	ipBindings = newIPBindingTable()

	// Unknown owner: a squatter gets the address first...
	if !ipBindings.OwnedBy(a.pub, ownerIP, true) {
		t.Fatal("setup: first-come claim should bind")
	}
	// ...a key that merely derives the address is not addressed in its
	// place...
	if ipBindings.OwnedBy(owner.pub, ownerIP, false) {
		t.Fatal("a key that never claimed the address was treated as its owner")
	}
	// ...the real owner, once it says it uses the address, can be addressed...
	setPeerOverlayIP(owner.pub, ownerIP)
	t.Cleanup(func() { nameMu.Lock(); delete(peerOverlayIPs, owner.pub); nameMu.Unlock() })
	ipBindings.dropVerdicts([]string{ownerIP}) // verdicts are cached for a few seconds
	if !ipBindings.OwnedBy(owner.pub, ownerIP, false) {
		t.Fatal("primary owner not addressable while a pinned claim holds its address")
	}
	// ...and its first authenticated packet displaces the squatter.
	if !ipBindings.OwnedBy(owner.pub, ownerIP, true) {
		t.Fatal("primary owner could not reclaim its address")
	}
	if ipBindings.OwnedBy(a.pub, ownerIP, true) {
		t.Fatal("squatter kept the address after the owner reclaimed it")
	}

	// A hopped (salted) address held by its node is NOT taken by a pinned claim.
	hop, _ := deriveOverlayIPSalted(overlayCIDR, a.pub, 25)
	hopIP := stripMask(hop)
	if !ipBindings.OwnedBy(a.pub, hopIP, true) {
		t.Fatal("hopped address (salt 25) refused")
	}
	b := testKeypair(t)
	if ipBindings.OwnedBy(b.pub, hopIP, true) {
		t.Fatal("pinned claim displaced a live hopped holder")
	}
}

// The field report: a phone that hopped to its 25th derived address and a
// container with a config-pinned address, both connected DIRECTLY, on a
// network with an admin key. Both must pass traffic in the default mode.
func TestHoppedPhoneAndPinnedPodAccepted(t *testing.T) {
	self, phone, pod := testKeypair(t), testKeypair(t), testKeypair(t)
	testNode(t, self, nil)
	ipBindingModeSetting = ipBindingDefault
	hop, _ := deriveOverlayIPSalted(overlayCIDR, phone.pub, 25)
	phoneIP := stripMask(hop)
	podIP := "10.22.99.22"
	for _, c := range []struct {
		kp   keypair
		ip   string
		port int
	}{{phone, phoneIP, 40201}, {pod, podIP, 40202}} {
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: c.port}
		GlobalSessions.set(addr, testPeerSession(t, gKP, c.kp, addr))
		handleControl(append([]byte{'A'}, []byte(c.ip)...), addr)
		if l := ipLearning.Lookup(c.ip); l == nil || l.String() != addr.String() {
			t.Fatalf("%s: announce not learned", c.ip)
		}
		if !sourceAllowedFrom(c.kp.pub, c.ip) {
			t.Fatalf("%s: data from its own node refused", c.ip)
		}
		if !ipBindings.OwnedBy(c.kp.pub, c.ip, false) {
			t.Fatalf("%s: egress would not send directly", c.ip)
		}
	}
}

func TestSelfAddressWarning(t *testing.T) {
	self := testKeypair(t)
	testNode(t, self, nil)
	ipBindingModeSetting = ipBindingStrict
	derived := myOverlayIP()

	checkSelfAddressVerifiable()
	if c := getIPConflict(); c != nil {
		t.Fatalf("derived address flagged: %+v", c)
	}
	pinned := "10.22.99.123"
	setMyOverlayIP(pinned)
	checkSelfAddressVerifiable()
	c := getIPConflict()
	if c == nil || c.Source != ipBindingSelfSource || c.Resolved || c.OldIP != pinned {
		t.Fatalf("pinned address not flagged: %+v", c)
	}
	// Collision housekeeping must not clear it.
	clearIPConflictIfSettled()
	if getIPConflict() == nil {
		t.Fatal("warning cleared by the collision resolver")
	}
	// Assigning it in the admin panel clears it.
	provisions.mu.Lock()
	provisions.recs[self.pub] = SignedProvision{PubKey: base64.StdEncoding.EncodeToString(self.pub[:]), Address: pinned, Seq: 1}
	provisions.mu.Unlock()
	checkSelfAddressVerifiable()
	if getIPConflict() != nil {
		t.Fatal("warning not cleared after the address was assigned")
	}
	// tofu mode never warns.
	provisions.mu.Lock()
	provisions.recs = map[[32]byte]SignedProvision{}
	provisions.mu.Unlock()
	ipBindingModeSetting = ipBindingDefault
	checkSelfAddressVerifiable()
	if getIPConflict() != nil {
		t.Fatal("warned in tofu mode")
	}
	setMyOverlayIP(derived)
}

// A raw key whose first or last byte is whitespace must load back unchanged.
func TestNodeKeyWithWhitespaceBytesReloads(t *testing.T) {
	dir := t.TempDir()
	for _, edge := range []byte{' ', '\n', '\t', '\r', '\v', '\f'} {
		path := dir + "/node.key"
		var raw [32]byte
		for i := range raw {
			raw[i] = byte(i + 100)
		}
		raw[0], raw[31] = edge, edge
		if err := os.WriteFile(path, raw[:], 0o600); err != nil {
			t.Fatal(err)
		}
		kp, err := loadOrCreateKey(path)
		if err != nil {
			t.Fatalf("edge byte %q: %v", edge, err)
		}
		if kp.priv != raw {
			t.Fatalf("edge byte %q: key altered on load", edge)
		}
	}
	// Hex keys (with a trailing newline) still load.
	path := dir + "/hex.key"
	os.WriteFile(path, []byte(strings.Repeat("ab", 32)+"\n"), 0o600)
	if _, err := loadOrCreateKey(path); err != nil {
		t.Fatalf("hex key: %v", err)
	}
}

// First contact through a relay with a device-set address: the roster is used
// when it is the only claim, but never in strict mode and never against a
// holder or a competing claim.
func TestOwnerOfPinnedFirstContact(t *testing.T) {
	self, b, other := testKeypair(t), testKeypair(t), testKeypair(t)
	testNode(t, self, nil)
	ipBindingModeSetting = ipBindingDefault
	pinned := "10.22.99.222"
	addRoster := func(k keypair) {
		rosterMu.Lock()
		rosterNodes[pinned+"#"+peerKeyFingerprint(k.pub[:])] = rosterView{rosterEntry: rosterEntry{IP: pinned, PK: base64.StdEncoding.EncodeToString(k.pub[:])}, Seen: time.Now()}
		rosterMu.Unlock()
	}
	addRoster(b)
	if k, ok := ipBindings.OwnerOf(pinned); !ok || k != b.pub {
		t.Fatal("single roster claim to a pinned address not used for first contact")
	}
	ipBindingModeSetting = ipBindingStrict
	if _, ok := ipBindings.OwnerOf(pinned); ok {
		t.Fatal("strict mode used a roster claim")
	}
	ipBindingModeSetting = ipBindingDefault
	addRoster(other)
	if _, ok := ipBindings.OwnerOf(pinned); ok {
		t.Fatal("contested roster claim used")
	}
	// Once b claims it itself, b is the owner regardless.
	if !ipBindings.OwnedBy(b.pub, pinned, true) {
		t.Fatal("b could not claim")
	}
	if k, ok := ipBindings.OwnerOf(pinned); !ok || k != b.pub {
		t.Fatal("bound owner not returned")
	}
}

// A relay whose key can DERIVE a device-set address (every key derives ~40%
// of a /24 through its collision-hop salts) must not be taken for that
// address's owner: traffic for it has to be sealed for the real holder, not
// handed to the relay in the clear, which can only drop it.
func TestDerivingAnAddressIsNotOwningIt(t *testing.T) {
	self, relay, holder := testKeypair(t), testKeypair(t), testKeypair(t)
	testNode(t, self, nil)
	ipBindingModeSetting = ipBindingDefault
	relayIP := testDerivedIP(t, relay.pub)
	var hopIP string
	for salt := 1; salt <= ipBindingMaxSalt && hopIP == ""; salt++ {
		a, err := deriveOverlayIPSalted(overlayCIDR, relay.pub, salt)
		if err != nil {
			t.Fatal(err)
		}
		if ip := stripMask(a); ip != relayIP && ip != myOverlayIP() {
			hopIP = ip
		}
	}
	setPeerOverlayIP(relay.pub, relayIP)
	t.Cleanup(func() {
		nameMu.Lock()
		delete(peerOverlayIPs, relay.pub)
		delete(peerOverlayIPs, holder.pub)
		nameMu.Unlock()
	})

	// The holder pinned hopIP and reached us through the relay.
	if !ipBindings.OwnedBy(holder.pub, hopIP, true) {
		t.Fatal("setup: holder could not claim its pinned address")
	}
	setPeerOverlayIP(holder.pub, hopIP)
	if ipBindings.OwnedBy(relay.pub, hopIP, false) {
		t.Fatal("relay treated as owner of an address it only derives")
	}
	if ipBindings.IsNodeAt(relay.pub, hopIP) {
		t.Fatal("relay treated as the node at the holder's address")
	}
	if !ipBindings.IsNodeAt(relay.pub, relayIP) {
		t.Fatal("relay not recognised at its own address")
	}
	if owner, ok := ipBindings.OwnerOf(hopIP); !ok || owner != holder.pub {
		t.Fatal("sealing key for the pinned address is not the holder's")
	}
}
