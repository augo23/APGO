package main

import (
	"os"
	"strings"
	"testing"
)

// TestReceivePathDeliversToTUN guards the single most consequential line in the
// client: the one that hands a frame addressed to this node to the OS tunnel.
//
// It is a source-level check rather than a behavioural one because the receive
// path lives in a closure (handleTransportPacket) built inside main() over a
// live UDP socket and TUN handle, and is not reachable from a unit test without
// restructuring it. A structural assertion that runs is worth more here than a
// perfect test that does not exist.
//
// The history this protects against: refactoring the read loop into
// handleTransportPacket turned every `continue` into a `return`. The delivery
// was not a statement in the loop body but its FALL-THROUGH, so there was no
// `continue` to convert -- it was simply lost. Everything still compiled and
// every test passed. Sessions established, control traffic flowed both ways,
// sends succeeded, routes were learned, and not one byte of payload was ever
// delivered, in either direction, for days.
func TestReceivePathDeliversToTUN(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	s := string(src)

	// The not-for-us branch must not be the last thing the receive path does.
	// Whatever follows it is the delivery, and it must write to the tunnel.
	const marker = "statRxDropNotForUs.Add(1)"
	i := strings.Index(s, marker)
	if i < 0 {
		t.Fatalf("receive path no longer contains %q — this guard needs updating", marker)
	}
	tail := s[i:]
	if !strings.Contains(tail, "tunIF.Write(pt)") {
		t.Error("the receive path drops frames addressed to THIS node: no tunIF.Write " +
			"follows the not-for-us branch. Frames for us must be written to the OS tunnel.")
	}
	if !strings.Contains(tail, "statRxDelivered.Add(1)") {
		t.Error("delivery on the direct receive path is not counted: statRxDelivered " +
			"must increment when a frame addressed to this node is delivered, or a dead " +
			"tunnel is indistinguishable from an idle one.")
	}
}

// TestDeliveryCountedOnBothPaths: frames reach the TUN via the direct path and
// via the end-to-end relay path (e2eDeliver, fed by the 'Z' frame handler).
// Both must count, or rx_delivered reads as 0 on a node whose traffic happens
// to arrive over the other one.
func TestDeliveryCountedOnBothPaths(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if n := strings.Count(string(src), "statRxDelivered.Add(1)"); n < 1 {
		t.Errorf("statRxDelivered is not incremented on the direct receive path")
	}
	glue, err := os.ReadFile("glue_node.go")
	if err != nil {
		t.Fatalf("read glue_node.go: %v", err)
	}
	g := string(glue)
	i := strings.Index(g, "func e2eDeliver(")
	if i < 0 {
		t.Fatal("glue_node.go no longer defines e2eDeliver — this guard needs updating")
	}
	body := g[i:]
	if !strings.Contains(body, "statRxDelivered.Add(1)") || !strings.Contains(body, "tunIF.Write(pkt)") {
		t.Error("the relay-delivery path (e2eDeliver) must write to the tunnel and count statRxDelivered")
	}
}
