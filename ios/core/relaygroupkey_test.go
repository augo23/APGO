package overlaymobile

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"testing"
)

// relayGroupKey MUST stay byte-identical to client/dht.go's dhtKey. If they
// diverge, a phone and a desktop on the same overlay present different groups
// to the relay — which only ever pairs within a group — and never meet, while
// both ends report healthy reservations. This reimplements the desktop
// derivation independently so a change to either copy fails loudly here.
func TestRelayGroupKeyMatchesDesktopDHTKey(t *testing.T) {
	psk := []byte("a-test-preshared-key")
	name := "sunairies-81ty5e5s-clean"

	m := hmac.New(sha1.New, psk)
	m.Write([]byte("apgo-dht-v1|"))
	m.Write([]byte(name))
	want := m.Sum(nil)[:20]

	got := relayGroupKey(name, psk)
	if !bytes.Equal(got, want) {
		t.Fatalf("relay group key diverged from the desktop's dhtKey\n got: %x\nwant: %x", got, want)
	}
}

// With no PSK both sides fall back to the plain infohash, and they must agree
// on that too.
func TestRelayGroupKeyFallsBackToInfoHash(t *testing.T) {
	name := "public-test-net"
	if !bytes.Equal(relayGroupKey(name, nil), deriveInfoHash(name)) {
		t.Fatal("PSK-less group key must equal deriveInfoHash, as it does on the desktop")
	}
}
