package main

import (
	"encoding/base64"
	"testing"
	"time"
)

func resetClaimState() {
	provisions.mu.Lock()
	provisions.recs = map[[32]byte]SignedProvision{}
	provisions.mu.Unlock()
	rosterMu.Lock()
	rosterNodes = map[string]rosterView{}
	rosterMu.Unlock()
	nameMu.Lock()
	peerOverlayIPs = map[[32]byte]string{}
	nameMu.Unlock()
	approvals.mu.Lock()
	approvals.recs = map[[32]byte]storedApproval{}
	approvals.mu.Unlock()
	ipConflictMu.Lock()
	ipConflictLast = nil
	ipConflictMu.Unlock()
}

func key(b byte) [32]byte {
	var k [32]byte
	k[0] = b
	return k
}

// A joining node must see an existing member's claim on the address it derived
// — from ANY of the three places such a claim shows up. Roster gossip is the
// one that matters most: it reaches a device before its (gated) data plane
// carries anything, which is the whole point.
func TestOverlayIPClaimsSeesAllSources(t *testing.T) {
	resetClaimState()
	ip := "10.22.22.50"

	if got := overlayIPClaims(ip); len(got) != 0 {
		t.Fatalf("clean state should have no claims, got %v", got)
	}

	other := key(0x11)
	rosterMu.Lock()
	rosterNodes[ip] = rosterView{
		rosterEntry: rosterEntry{IP: ip, PK: base64.StdEncoding.EncodeToString(other[:])},
		Seen:        time.Now(),
	}
	rosterMu.Unlock()
	got := overlayIPClaims(ip)
	if len(got) != 1 || got[0].pub != other || got[0].source != "roster" {
		t.Fatalf("roster claim not seen: %+v", got)
	}

	// A direct peer announcing the same address is the same node, not a second
	// claimant — dedup is by KEY, or the banner would double-count.
	nameMu.Lock()
	peerOverlayIPs[other] = ip
	nameMu.Unlock()
	if got := overlayIPClaims(ip); len(got) != 1 {
		t.Fatalf("same key from two sources must dedupe, got %+v", got)
	}

	// An admin provision upgrades the claim rather than adding one.
	provisions.mu.Lock()
	provisions.recs[other] = SignedProvision{
		PubKey: base64.StdEncoding.EncodeToString(other[:]), Address: ip + "/24", Seq: 1,
	}
	provisions.mu.Unlock()
	got = overlayIPClaims(ip)
	if len(got) != 1 || !got[0].provisoned {
		t.Fatalf("provision should mark the claim as admin-assigned, got %+v", got)
	}

	// Our own claim on our own address is never a conflict.
	provisions.mu.Lock()
	provisions.recs[gKP.pub] = SignedProvision{
		PubKey: base64.StdEncoding.EncodeToString(gKP.pub[:]), Address: "10.22.22.51/24", Seq: 1,
	}
	provisions.mu.Unlock()
	if got := overlayIPClaims("10.22.22.51"); len(got) != 0 {
		t.Fatalf("self claim must not conflict with itself, got %+v", got)
	}
}

// The yield rule decides WHICH of two colliding nodes moves. Getting this
// backwards would re-address a live, approved member to make room for a device
// that has not been admitted yet.
func TestYieldsToPrefersTheIncumbent(t *testing.T) {
	resetClaimState()

	if !yieldsTo(ipClaim{pub: key(0x22), provisoned: true}) {
		t.Error("an admin-assigned address must always win")
	}

	// With equal standing the tie-break is the key comparison, and it is a
	// strict order: the node with the larger key moves, so exactly one of the
	// two sides yields and both compute the same answer. This node's test key
	// is the zero key, so nothing outranks it here.
	if yieldsTo(ipClaim{pub: key(0xff)}) {
		t.Error("the lower key must keep the address")
	}
}

// The reinstall case, which is the one that actually happens: a machine comes
// back with a NEW node key, an admin re-provisions its usual address onto that
// key, and the OLD key's record is still floating around. The new key holds the
// newer signature, so it must keep the address — reading the leftover record as
// an authority would move a correctly-provisioned device off the address it was
// just given.
func TestYieldsToNewestProvisionWins(t *testing.T) {
	resetClaimState()
	ip := "10.22.22.115"
	setMyOverlayIP(ip)
	defer setMyOverlayIP("")

	old := key(0x77)
	stale := ipClaim{pub: old, provisoned: true, seq: 100}
	if !yieldsTo(stale) {
		t.Fatal("with no provision of our own, an admin-assigned claim wins")
	}

	// Admin re-provisions the address onto THIS key, with a later signature.
	provisions.mu.Lock()
	provisions.recs[gKP.pub] = SignedProvision{
		PubKey:  base64.StdEncoding.EncodeToString(gKP.pub[:]),
		Address: ip + "/24", Seq: 200,
	}
	provisions.mu.Unlock()
	if yieldsTo(stale) {
		t.Error("our newer provision must supersede the old key's claim")
	}
	if !yieldsTo(ipClaim{pub: old, provisoned: true, seq: 300}) {
		t.Error("a genuinely newer claim still wins")
	}
}

// A claim from a key that nothing has heard from is a ghost, and the resolver
// has to be able to tell — it is the difference between "move off this address"
// and "reclaim this address".
func TestClaimantIsLiveFalseWithoutSessionOrRoster(t *testing.T) {
	resetClaimState()
	if claimantIsLive(key(0x42)) {
		t.Error("a key with no session and no roster entry is not live")
	}
}

// A revoked key's claim is not a claim.
func TestOverlayIPClaimsIgnoresRevokedKeys(t *testing.T) {
	resetClaimState()
	ip := "10.22.22.60"
	gone := key(0x33)
	provisions.mu.Lock()
	provisions.recs[gone] = SignedProvision{
		PubKey: base64.StdEncoding.EncodeToString(gone[:]), Address: ip, Seq: 1,
	}
	provisions.mu.Unlock()
	if len(overlayIPClaims(ip)) != 1 {
		t.Fatal("setup: the claim should be visible before revocation")
	}
	revocations.applyLocal(gone, "revoke")
	defer revocations.removeLocal(gone)
	if got := overlayIPClaims(ip); len(got) != 0 {
		t.Errorf("a revoked key must not hold an address, got %+v", got)
	}
}
