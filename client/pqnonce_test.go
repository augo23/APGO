package main

import (
	"crypto/rand"
	"testing"
)

// Nonces must never repeat for one key. The old code drew a fresh random nonce
// per packet (a syscall on every datagram); the replacement is salt+counter, so
// the property has to be asserted rather than assumed.
func TestPQNonceNeverRepeats(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	aead, err := pqAEADFromSecret(key)
	if err != nil {
		t.Fatal(err)
	}
	p := newPQPeer(aead)
	seen := map[string]bool{}
	n := make([]byte, aead.NonceSize())
	for i := 0; i < 100000; i++ {
		s := string(p.nextNonce(n))
		if seen[s] {
			t.Fatalf("nonce repeated after %d packets", i)
		}
		seen[s] = true
	}
	// A NEW key must restart against a fresh salt, so its nonces cannot
	// collide with the previous key's counter values.
	q := newPQPeer(aead)
	if q.nonceSalt == p.nonceSalt {
		t.Error("a re-keyed peer reused the previous salt")
	}
}

// The pooled wrap path must produce exactly what the allocating path did, and
// must survive buffer reuse across calls (the bug a pool invites).
func TestPQWrapPooledBufferRoundTrips(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	aead, err := pqAEADFromSecret(key)
	if err != nil {
		t.Fatal(err)
	}
	var peer [32]byte
	peer[0] = 9
	pqMu.Lock()
	pqPeers[peer] = newPQPeer(aead)
	pqMu.Unlock()
	defer func() { pqMu.Lock(); delete(pqPeers, peer); pqMu.Unlock() }()

	scratch := make([]byte, maxFrameSize)
	for i, size := range []int{1, 64, 1280, 1500, 9000} {
		want := make([]byte, size)
		for j := range want {
			want[j] = byte(i*7 + j)
		}
		w, ok := pqWrapTo(scratch[:0], peer, want)
		if !ok {
			t.Fatalf("size %d: wrap failed", size)
		}
		if !isPQPacket(w) {
			t.Fatalf("size %d: wrapped frame lost its magic", size)
		}
		got, ok := pqUnwrap(peer, w)
		if !ok {
			t.Fatalf("size %d: unwrap failed", size)
		}
		if string(got) != string(want) {
			t.Fatalf("size %d: round trip corrupted the packet", size)
		}
	}
}

// The whole point of the change: the steady-state packet path must not
// allocate. A regression here is invisible until a phone stalls mid-transfer.
func TestPQWrapDoesNotAllocate(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	aead, err := pqAEADFromSecret(key)
	if err != nil {
		t.Fatal(err)
	}
	var peer [32]byte
	peer[0] = 11
	pqMu.Lock()
	pqPeers[peer] = newPQPeer(aead)
	pqMu.Unlock()
	defer func() { pqMu.Lock(); delete(pqPeers, peer); pqMu.Unlock() }()

	scratch := make([]byte, maxFrameSize)
	pkt := make([]byte, 1280)
	if n := testing.AllocsPerRun(200, func() {
		w, _ := pqWrapTo(scratch[:0], peer, pkt)
		pqUnwrap(peer, w)
	}); n > 0 {
		t.Errorf("PQ wrap+unwrap allocates %.0f times per packet, want 0", n)
	}
}
