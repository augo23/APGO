package main

import (
	"bytes"
	"testing"
	"time"
)

func pqHealReset(t *testing.T) {
	t.Helper()
	oldEnabled, oldKP := pqEnabled, gKP
	pqHealMu.Lock()
	pqHealPeers = map[[32]byte]*pqHealPeer{}
	pqHealCount = 0
	pqHealMu.Unlock()
	pqEnabled = true
	t.Cleanup(func() {
		pqEnabled, gKP = oldEnabled, oldKP
		pqHealMu.Lock()
		pqHealPeers = map[[32]byte]*pqHealPeer{}
		pqHealMu.Unlock()
	})
}

func establishedPQ(t *testing.T, peer [32]byte) {
	t.Helper()
	aead, err := pqAEADFromSecret(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	pqMu.Lock()
	pqPeers[peer] = newPQPeer(aead)
	pqMu.Unlock()
	t.Cleanup(func() { pqForget(peer) })
}

func backdateEstablished(peer [32]byte, d time.Duration) {
	pqHealMu.Lock()
	pqHealGet(peer).established = time.Now().Add(-d)
	pqHealMu.Unlock()
}

// A responder that restarted sends classical frames; the offerer holding the
// old key must drop it after a few of them (and not after one).
func TestPQHealOffererDropsKeyOnClassicalFrames(t *testing.T) {
	pqHealReset(t)
	gKP.pub = [32]byte{1} // smaller key: we are the offerer
	peer := [32]byte{9}
	if !pqInitiator(peer) {
		t.Fatal("test setup: expected to be the offerer")
	}
	establishedPQ(t, peer)
	pqHealEstablished(peer)
	backdateEstablished(peer, time.Minute)

	data := []byte{0x45, 0, 0, 20}
	for i := 0; i < pqHealThreshold-1; i++ {
		pqHealClassical(peer, nil, data)
	}
	if !pqReady(peer) {
		t.Fatal("key dropped before the threshold")
	}
	pqHealClassical(peer, nil, data)
	if pqReady(peer) {
		t.Fatal("stale key kept after a run of classical frames")
	}
	if pqHealRenegotiations() != 1 {
		t.Fatalf("renegotiations = %d, want 1", pqHealRenegotiations())
	}
}

func TestPQHealIgnoresNegotiationAndResponderRole(t *testing.T) {
	pqHealReset(t)
	gKP.pub = [32]byte{9} // larger key: we are the responder
	peer := [32]byte{1}
	establishedPQ(t, peer)
	backdateEstablished(peer, time.Minute)
	for i := 0; i < 10; i++ {
		pqHealClassical(peer, nil, []byte{0x45, 0, 0, 20})
	}
	if !pqReady(peer) {
		t.Fatal("responder must not act on classical frames (the offerer re-offers)")
	}

	gKP.pub = [32]byte{0} // offerer again
	offer := append(append([]byte(nil), ctlMagic...), 'M', 1, 2, 3)
	reset := append(append([]byte(nil), ctlMagic...), pqResetFrame, 1)
	for i := 0; i < 10; i++ {
		pqHealClassical(peer, nil, offer)
		pqHealClassical(peer, nil, reset)
	}
	if !pqReady(peer) {
		t.Fatal("negotiation frames travel classically and must not count")
	}
}

func TestPQHealSettleAndRateLimit(t *testing.T) {
	pqHealReset(t)
	gKP.pub = [32]byte{1}
	peer := [32]byte{9}
	establishedPQ(t, peer)
	pqHealEstablished(peer) // just now: settle window
	for i := 0; i < 10; i++ {
		pqHealUnopenable(peer, nil)
	}
	if !pqReady(peer) {
		t.Fatal("acted inside the settle window")
	}
	backdateEstablished(peer, time.Minute)
	for i := 0; i < pqHealThreshold; i++ {
		pqHealUnopenable(peer, nil)
	}
	if pqReady(peer) || pqHealRenegotiations() != 1 {
		t.Fatalf("expected one renegotiation, got %d", pqHealRenegotiations())
	}
	// Re-established by a (simulated) exchange, then broken again at once:
	// rate-limited.
	establishedPQ(t, peer)
	backdateEstablished(peer, time.Minute)
	for i := 0; i < 3*pqHealThreshold; i++ {
		pqHealUnopenable(peer, nil)
	}
	if pqHealRenegotiations() != 1 {
		t.Fatalf("rate limit not applied: %d renegotiations", pqHealRenegotiations())
	}
}

// While our own offer is in flight the responder already wraps with the new
// key; those frames must not tear down the pending offer.
func TestPQHealPendingOfferNotDisturbed(t *testing.T) {
	pqHealReset(t)
	gKP.pub = [32]byte{1}
	peer := [32]byte{9}
	t.Cleanup(func() { pqForget(peer) })
	if buildPQOffer(peer) == nil {
		t.Fatal("no offer built")
	}
	for i := 0; i < 3*pqHealThreshold; i++ {
		pqHealUnopenable(peer, nil)
	}
	if p := pqGet(peer); p == nil || p.priv == nil {
		t.Fatal("pending offer was discarded")
	}
	if pqHealRenegotiations() != 0 {
		t.Fatal("renegotiated while an offer was pending")
	}
}

// The renegotiate request must survive handleControl's minimum length and
// never be wrapped.
func TestPQResetFrameShape(t *testing.T) {
	f := append(append([]byte(nil), ctlMagic...), pqResetFrame, 1)
	if !isPQNegotiation(f) {
		t.Fatal("reset frame would be PQ-wrapped")
	}
	if body := f[len(ctlMagic):]; len(body) < 2 {
		t.Fatal("reset frame too short for handleControl")
	}
}
