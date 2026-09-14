package main

import (
	"bytes"
	"testing"
)

// The relay directory key is a cross-implementation contract: the desktop
// publishes under it and the mobile core looks it up. If the two ever differ,
// both halves look healthy — the desktop holds reservations, the phone holds
// reservations — and they simply never meet. Pin the exact bytes so a
// well-meaning edit to either copy fails here instead of in the field.
func TestRelayDirectoryKeyIsStable(t *testing.T) {
	want := []byte{
		0xc3, 0x94, 0x99, 0x54, 0x37, 0xa0, 0xfb, 0xe7, 0x6f, 0xf8,
		0x42, 0xf0, 0x01, 0x83, 0x29, 0xa9, 0x76, 0xc5, 0xa0, 0x40,
	}
	got := relayDirectoryKey()
	if len(got) != 20 {
		t.Fatalf("directory key must be 20 bytes, got %d", len(got))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("relay directory key changed!\n got: %x\nwant: %x\n"+
			"Both client/publicrelay.go and ios/core/relayclient.go derive this "+
			"from the string \"apgo-public-relay-directory-v1\"; changing one "+
			"without the other silently separates desktops from phones.", got, want)
	}
}

// A relay we cannot reach from the public internet is worse than no relay: it
// consumes one of relayClientMaxRelays slots and can never forward a packet.
func TestRelayDirectoryRejectsUnusableEndpoints(t *testing.T) {
	for _, bad := range []string{
		"192.168.1.10:6969",  // RFC1918: another node's LAN, echoed by a tracker
		"10.22.22.5:6969",    // an overlay address — never a transport
		"127.0.0.1:6969",     // loopback
		"169.254.10.10:6969", // link-local
		"not-an-endpoint",
	} {
		if isValidPeer(bad) {
			t.Errorf("%q must not be accepted as a relay endpoint", bad)
		}
	}
	if !isValidPeer("38.131.232.196:40343") {
		t.Error("a routable public endpoint must be accepted as a relay")
	}
}

// Discovery must be a no-op rather than a panic when there is nothing to ask.
func TestRelayDirectoryPeersWithNoTrackers(t *testing.T) {
	if got := relayDirectoryPeers(nil, 0); got != nil {
		t.Fatalf("no trackers should yield no endpoints, got %v", got)
	}
	if got := relayDirectoryPeers([]string{"", "   "}, 0); len(got) != 0 {
		t.Fatalf("blank trackers should yield no endpoints, got %v", got)
	}
}

// Unknown schemes must be skipped, not dialed. A tracker list is operator- and
// gossip-supplied, so it will contain junk.
func TestRelayDirectoryIgnoresUnknownSchemes(t *testing.T) {
	if got := relayDirectoryPeers([]string{"ftp://nope/announce", "wss://also-no"}, 0); len(got) != 0 {
		t.Fatalf("unknown schemes must be ignored, got %v", got)
	}
}
