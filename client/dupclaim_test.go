package main

import (
	"encoding/base64"
	"testing"
)

// A stale provision left behind by a reinstall silently black-holes every
// packet addressed to the node, while every visible indicator stays green.
// This is the check that makes it say so out loud.
func TestOverlayIPClaimantsFindsStaleProvision(t *testing.T) {
	provisions.mu.Lock()
	provisions.recs = map[[32]byte]SignedProvision{}
	provisions.mu.Unlock()

	self := base64.StdEncoding.EncodeToString(gKP.pub[:])
	var oldKey [32]byte
	oldKey[0] = 0x99
	oldB64 := base64.StdEncoding.EncodeToString(oldKey[:])

	// Our own provision for the address is never a conflict.
	provisions.recs[gKP.pub] = SignedProvision{PubKey: self, Address: "10.22.22.115/24", Seq: 2}
	if got := overlayIPClaimants("10.22.22.115"); len(got) != 0 {
		t.Errorf("our own provision must not count as a claimant, got %v", got)
	}

	// A DIFFERENT key holding the same address is the bug.
	provisions.recs[oldKey] = SignedProvision{PubKey: oldB64, Address: "10.22.22.115", Seq: 1}
	got := overlayIPClaimants("10.22.22.115")
	if len(got) != 1 || got[0] != oldB64 {
		t.Fatalf("expected the stale key to be reported, got %v", got)
	}

	// Address forms must match with or without a CIDR suffix — the two are
	// written inconsistently across config, provisions and the wire, and
	// missing that would make this check silently useless.
	if got := overlayIPClaimants("10.22.22.115/24"); len(got) != 1 {
		t.Errorf("CIDR form should match the bare form, got %v", got)
	}
	// An unrelated address is clean.
	if got := overlayIPClaimants("10.22.22.116"); len(got) != 0 {
		t.Errorf("unrelated address should have no claimants, got %v", got)
	}
	if got := overlayIPClaimants(""); len(got) != 0 {
		t.Errorf("empty address should have no claimants, got %v", got)
	}
}
