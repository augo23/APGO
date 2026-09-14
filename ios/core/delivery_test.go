package overlaymobile

import (
	"os"
	"strings"
	"testing"
)

// THE HISTORY THIS PROTECTS AGAINST (see client/delivery_test.go, which guards
// the same invariant on the desktop):
//
// Refactoring the read loop into handleTransportPacket turns every `continue`
// into a `return`. The final TUN delivery is not a statement in the loop body
// but its FALL-THROUGH, so there is no `continue` to convert — it is simply
// lost. Everything still compiles and every test passes. Sessions establish,
// control traffic flows both ways, sends succeed, routes are learned, and not
// one byte of payload is ever delivered, in either direction, for days.
//
// The iOS core has now had exactly that refactor, to let relay-delivered
// frames share the receive path (relayclient.go). So it needs the same guard.
//
// This is a source-level assertion rather than a behavioural one because the
// receive path needs a live TUN handle and session table; a structural check
// that runs is worth more than a perfect test that does not exist.
func TestReceivePathDeliversToTUN(t *testing.T) {
	src, err := os.ReadFile("transportpath.go")
	if err != nil {
		t.Fatalf("read transportpath.go: %v", err)
	}
	s := string(src)

	i := strings.Index(s, "func handleTransportPacket")
	if i < 0 {
		t.Fatal("handleTransportPacket is gone: if the receive path moved, move this test with it")
	}
	body := s[i:]

	// The unconditional trailing delivery to the OS tunnel.
	if !strings.Contains(body, "tunIF.Write(pt)") {
		t.Fatal("handleTransportPacket no longer writes payload to the TUN — " +
			"the fall-through delivery was lost in a refactor")
	}

	// …and it must be the LAST statement, not stranded inside a branch that
	// an early return can skip. Checking the tail is what distinguishes
	// "delivery happens for every admitted packet" from "delivery happens for
	// the one case someone remembered".
	tail := strings.TrimSpace(body[strings.LastIndex(body, "tunIF.Write(pt)"):])
	if !strings.HasPrefix(tail, "tunIF.Write(pt)\n}") {
		t.Fatalf("the final TUN delivery must be the last statement of "+
			"handleTransportPacket; found: %.60q", tail)
	}
}

// The relay path must reuse that same handler rather than reimplementing it.
// A second copy is how a relayed peer ends up quietly exempt from admission
// control or PQ unwrapping.
func TestRelayDeliveryReusesTheReceivePath(t *testing.T) {
	src, err := os.ReadFile("run.go")
	if err != nil {
		t.Fatalf("read run.go: %v", err)
	}
	if !strings.Contains(string(src), "gTransportDeliver = func(") ||
		!strings.Contains(string(src), "handleTransportPacket(p, ra, kp, psk)") {
		t.Fatal("relay-delivered frames must be routed through handleTransportPacket, " +
			"so they take the same handshake/admission/routing path as direct ones")
	}
}
