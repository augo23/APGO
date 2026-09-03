package main

import (
	"net"
	"testing"
)

// A relay circuit's synthetic address must never become a learned route.
//
// When it did, the egress path resolved a peer to the circuit and overlayWriteTo
// diverted its traffic off the socket entirely — a node that looked fully
// connected (sessions, PQ, gossip all fine) and could not move a single packet,
// because control frames bypass this table and data frames do not.
func TestLearnRejectsSyntheticRelayAddresses(t *testing.T) {
	tbl := NewIPLearningTable()

	real4, _ := net.ResolveUDPAddr("udp", "203.0.113.9:6969")
	tbl.Learn("10.22.22.3", real4)
	if got := tbl.Lookup("10.22.22.3"); got == nil || got.String() != real4.String() {
		t.Fatalf("a real endpoint must be learned, got %v", got)
	}

	// The circuit address relayclient.go hands to the transport handler.
	synth := synthAddrFor(0x1234)
	tbl.Learn("10.22.22.7", synth)
	if got := tbl.Lookup("10.22.22.7"); got != nil {
		t.Errorf("a 240/4 circuit address must never be installed as a route, got %v", got)
	}

	// And it must not be able to DISPLACE a good route either.
	tbl.Learn("10.22.22.3", synth)
	if got := tbl.Lookup("10.22.22.3"); got == nil || got.String() != real4.String() {
		t.Errorf("an existing real route must survive a synthetic Learn, got %v", got)
	}
}
