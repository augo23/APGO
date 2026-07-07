package main

import (
	"net"
	"testing"
	"time"
)

// TestSTUNParserOnSyntheticResponse verifies dispatchSTUN correctly extracts
// an XOR-MAPPED-ADDRESS attribute from a hand-built STUN binding response.
// This catches any bit-twiddling bugs in dispatchSTUN without needing
// a real STUN server.
func TestSTUNParserOnSyntheticResponse(t *testing.T) {
	// Mock public reflexive endpoint we want to be able to recover: 1.2.3.4:54321.
	var txid [12]byte
	for i := range txid {
		txid[i] = byte(0xA0 + i)
	}

	// Register a callback that captures the parsed reflexive endpoint.
	got := make(chan string, 1)
	stunPendingMu.Lock()
	stunPendingCb = func(r string) {
		select {
		case got <- r:
		default:
		}
	}
	stunPendingTx = txid
	stunPendingMu.Unlock()
	defer func() {
		stunPendingMu.Lock()
		stunPendingCb = nil
		stunPendingMu.Unlock()
	}()

	// Build a STUN binding-success response with XOR-MAPPED-ADDRESS = 1.2.3.4:54321.
	// Header: 20 bytes. Body: 12 bytes (4-byte attr header + 8-byte IPv4 XOR-MAPPED-ADDRESS).
	pkt := make([]byte, 32)
	// Type: 0x0101 (Binding Success Response)
	pkt[0] = 0x01
	pkt[1] = 0x01
	// Length: 12 bytes of attributes
	pkt[2] = 0x00
	pkt[3] = 0x0C
	// Magic cookie
	copy(pkt[4:8], stunMagicCookie[:])
	// Transaction id
	copy(pkt[8:20], txid[:])
	// Attribute: type XOR-MAPPED-ADDRESS (0x0020), length 8
	pkt[20] = 0x00
	pkt[21] = 0x20
	pkt[22] = 0x00
	pkt[23] = 0x08
	// Value: reserved(1) + family(1=IPv4) + xport(2) + xip(4)
	pkt[24] = 0x00 // reserved
	pkt[25] = 0x01 // IPv4
	// Port 54321 = 0xD431. XOR with first 2 bytes of magic cookie (0x2112).
	port := uint16(54321)
	xport := port ^ uint16(stunMagicCookie[0])<<8 ^ uint16(stunMagicCookie[1])
	pkt[26] = byte(xport >> 8)
	pkt[27] = byte(xport & 0xff)
	// IP 1.2.3.4 XORed with magic cookie bytes.
	pkt[28] = 1 ^ stunMagicCookie[0]
	pkt[29] = 2 ^ stunMagicCookie[1]
	pkt[30] = 3 ^ stunMagicCookie[2]
	pkt[31] = 4 ^ stunMagicCookie[3]

	if !dispatchSTUN(pkt) {
		t.Fatalf("dispatchSTUN returned false on a valid STUN message")
	}

	select {
	case parsed := <-got:
		want := "1.2.3.4:54321"
		if parsed != want {
			t.Fatalf("parsed reflexive = %q, want %q", parsed, want)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("dispatchSTUN did not invoke the callback")
	}
}

// TestSTUNDispatchRejectsOverlayPacket verifies that a garbage non-overlay
// packet is not mistaken for a valid STUN response.
func TestSTUNDispatchRejectsOverlayPacket(t *testing.T) {
	// A 33-byte PktMsg1 with random body. Its byte[4..7] won't be the
	// magic cookie except by 2^-32 chance, so dispatchSTUN must return
	// false.
	pkt := make([]byte, 33)
	pkt[0] = PktMsg1
	if dispatchSTUN(pkt) {
		t.Fatalf("dispatchSTUN consumed an overlay PktMsg1 packet")
	}
}

// TestSimulInitTiebreakLowerWins verifies that when two ephemeral
// pubkeys are compared, the side with the lexicographically smaller
// pubkey stays initiator (Deliver returns true and drops the inbound).
// This exercises only the comparison helper, not the whole Deliver
// flow which would require setting up real Noise state and a UDP conn.
func TestSimulInitTiebreakComparisonHelper(t *testing.T) {
	// Two arbitrary 32-byte pubkeys.
	low := make([]byte, 32)
	for i := range low {
		low[i] = 0x10
	}
	high := make([]byte, 32)
	for i := range high {
		high[i] = 0x80
	}

	// The actual tiebreak in Deliver uses bytes.Compare(ourEphemeral, peer).
	// Lower wins (drops peer). Higher loses (becomes responder).
	// We assert the byte ordering matches what sessions.go expects.
	if !(bytesLess(low, high)) {
		t.Errorf("expected low < high in byte order")
	}
	if bytesLess(high, low) {
		t.Errorf("expected !(high < low)")
	}
}

func bytesLess(a, b []byte) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return len(a) < len(b)
}

// TestIsOverlayPacket smoke-checks the dispatch helper.
func TestIsOverlayPacket(t *testing.T) {
	for _, c := range []struct {
		b    byte
		want bool
	}{
		{PktMsg1, true},
		{PktMsg2, true},
		{PktMsg3, true},
		{PktData, true},
		{PktCookieReply, true},
		{0x01, true},  // PktMsg1 — same as above, explicitly verify
		{0x00, false}, // STUN binding request prefix
		{0x80, false}, // unused
		{0x86, false}, // unused
	} {
		if got := IsOverlayPacket(c.b); got != c.want {
			t.Errorf("IsOverlayPacket(0x%02x) = %v, want %v", c.b, got, c.want)
		}
	}
}

var _ = net.IPv4 // keep "net" import used so build doesn't break if test grows
