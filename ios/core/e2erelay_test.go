package overlaymobile

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Crypto-level tests for the shared e2erelay.go (node-level behaviour is
// covered by the identical code's tests in client/).

func testKeypair(t *testing.T) keypair {
	t.Helper()
	var kp keypair
	if _, err := rand.Read(kp.priv[:]); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(kp.priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(kp.pub[:], pub)
	return kp
}

func testIPv4(src, dst string, payload []byte) []byte {
	p := make([]byte, 20+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = 64
	p[9] = 17
	copy(p[12:16], net.ParseIP(src).To4())
	copy(p[16:20], net.ParseIP(dst).To4())
	copy(p[20:], payload)
	return p
}

// --- helpers for the crypto layer ----------------------------------------------

func ip4(s string) [4]byte { v, _ := ipv4To4(s); return v }

// testPQExchange runs A's ML-KEM offer to B in memory and returns A's secret;
// B's table then holds the matching one.
func testPQExchange(t *testing.T, aPQ, bPQ *e2ePQ, a, b [32]byte) *e2ePQSecret {
	t.Helper()
	now := time.Now()
	cur, offer := aPQ.outbound(b, now)
	if cur != nil || offer == nil || offer[0] != e2eKindOffer {
		t.Fatal("expected an offer and no secret yet")
	}
	reply, err := bPQ.onOffer(a, offer[1:], now)
	if err != nil {
		t.Fatal(err)
	}
	if err := aPQ.onReply(b, reply[1:], now); err != nil {
		t.Fatal(err)
	}
	cur, offer = aPQ.outbound(b, now)
	if cur == nil || offer != nil {
		t.Fatal("secret not ready after the exchange")
	}
	return cur
}

func lookupIn(p *e2ePQ) e2ePQLookup {
	return func(s [32]byte, id [4]byte) *[32]byte { return p.secretFor(s, id, time.Now()) }
}

func noPQLookup([32]byte, [4]byte) *[32]byte { return nil }

// testPQPair sets up a ready A->B secret and returns A's secret plus B's lookup.
func testPQPair(t *testing.T, a, b keypair) (*e2ePQSecret, e2ePQLookup) {
	aPQ, bPQ := newE2EPQ(), newE2EPQ()
	return testPQExchange(t, aPQ, bPQ, a.pub, b.pub), lookupIn(bPQ)
}

// --- crypto unit tests -----------------------------------------------------------

func TestE2ESealOpenRoundTrip(t *testing.T) {
	a, b, eve := testKeypair(t), testKeypair(t), testKeypair(t)
	psk := []byte("network-secret")
	now := time.Now()
	pq, bLookup := testPQPair(t, a, b)
	pkt := testIPv4("10.22.22.1", "10.22.22.9", []byte("hello through a relay"))

	frame, err := newE2ESealer().seal(a, psk, b.pub, ip4("10.22.22.9"), ip4("10.22.22.1"), pq, pkt, now)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(frame, []byte("hello through a relay")) {
		t.Fatal("payload visible in the sealed frame")
	}
	body := frame[len(ctlMagic)+1:]

	// A relay (eve) cannot open it, even knowing the PSK.
	if _, _, err := newE2EOpener().open(eve, psk, append([]byte(nil), body...), eve.pub, bLookup, now); err == nil {
		t.Fatal("a non-recipient opened the frame")
	}
	// Wrong PSK cannot open it.
	if _, _, err := newE2EOpener().open(b, []byte("other"), append([]byte(nil), body...), eve.pub, bLookup, now); err == nil {
		t.Fatal("opened with the wrong PSK")
	}
	// Without the ML-KEM secret it cannot be opened, even with B's static key.
	if _, _, err := newE2EOpener().open(b, psk, append([]byte(nil), body...), eve.pub, noPQLookup, now); err != errE2ENoPQ {
		t.Fatalf("without the PQ secret: got %v, want errE2ENoPQ", err)
	}
	// A wrong ML-KEM secret under the right id fails authentication.
	wrong := func([32]byte, [4]byte) *[32]byte { var z [32]byte; z[0] = 1; return &z }
	if _, _, err := newE2EOpener().open(b, psk, append([]byte(nil), body...), eve.pub, wrong, now); err != errE2EAuth {
		t.Fatalf("wrong PQ secret: got %v, want errE2EAuth", err)
	}
	// The recipient can, and learns the authenticated sender.
	op := newE2EOpener()
	h, pt, err := op.open(b, psk, append([]byte(nil), body...), eve.pub, bLookup, now)
	if err != nil {
		t.Fatalf("recipient could not open: %v", err)
	}
	if h.sender != a.pub || !bytes.Equal(pt, pkt) || h.dst != ip4("10.22.22.9") || h.src != ip4("10.22.22.1") || !h.hasPQ() {
		t.Fatal("wrong sender, addresses, PQ flag or plaintext")
	}
	// Replay is refused.
	if _, _, err := op.open(b, psk, append([]byte(nil), body...), eve.pub, bLookup, now); err != errE2EReplay {
		t.Fatalf("replay: got %v, want errE2EReplay", err)
	}
}

func TestE2ERelayMayOnlyChangeHop(t *testing.T) {
	a, b := testKeypair(t), testKeypair(t)
	psk := []byte("k")
	now := time.Now()
	pq, bLookup := testPQPair(t, a, b)
	frame, _ := newE2ESealer().seal(a, psk, b.pub, ip4("10.22.22.9"), ip4("10.22.22.1"), pq, testIPv4("10.22.22.1", "10.22.22.9", []byte("x")), now)
	base := frame[len(ctlMagic)+1:]

	hop := append([]byte(nil), base...)
	hop[e2eOffHop] = 1
	if _, _, err := newE2EOpener().open(b, psk, hop, a.pub, bLookup, now); err != nil {
		t.Fatalf("hop change must stay valid: %v", err)
	}
	for _, off := range []int{e2eOffVer, e2eOffDst, e2eOffSrc, e2eOffSender, e2eOffEph, e2eOffTS, e2eOffCtr, e2eOffPQID, e2eHeaderLen, len(base) - 1} {
		m := append([]byte(nil), base...)
		m[off] ^= 0x01
		if _, _, err := newE2EOpener().open(b, psk, m, a.pub, bLookup, now); err == nil {
			t.Errorf("tampering byte %d was not detected", off)
		}
	}
}

func TestE2ESenderCannotBeForged(t *testing.T) {
	// An insider relay that knows A's PUBLIC key and the PSK tries to seal a
	// packet "from A". It even completed its own ML-KEM exchange with B
	// under A's name — which B would only accept from A, but assume it.
	a, b, eve := testKeypair(t), testKeypair(t), testKeypair(t)
	psk := []byte("shared network psk")
	now := time.Now()
	ePQ, bPQ := newE2EPQ(), newE2EPQ()
	pq := testPQExchange(t, ePQ, bPQ, a.pub, b.pub)
	forger := eve
	forger.pub = a.pub // header says A, but the static DH uses eve's private key
	frame, err := newE2ESealer().seal(forger, psk, b.pub, ip4("10.22.22.9"), ip4("10.22.22.1"), pq, testIPv4("10.22.22.1", "10.22.22.9", []byte("x")), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := newE2EOpener().open(b, psk, frame[len(ctlMagic)+1:], eve.pub, lookupIn(bPQ), now); err == nil {
		t.Fatal("a forged sender identity was accepted")
	}
}

func TestE2EStaleAndFutureKeysRejected(t *testing.T) {
	a, b := testKeypair(t), testKeypair(t)
	psk := []byte("k")
	pq, bLookup := testPQPair(t, a, b)
	for _, skew := range []time.Duration{-e2eMaxSkew - time.Minute, e2eMaxSkew + time.Minute} {
		frame, _ := newE2ESealer().seal(a, psk, b.pub, ip4("10.22.22.9"), ip4("10.22.22.1"), pq, testIPv4("10.22.22.1", "10.22.22.9", nil), time.Now().Add(skew))
		if _, _, err := newE2EOpener().open(b, psk, frame[len(ctlMagic)+1:], a.pub, bLookup, time.Now()); err != errE2EStale {
			t.Errorf("skew %v: got %v, want errE2EStale", skew, err)
		}
	}
}

func TestE2EKeyRotation(t *testing.T) {
	a, b := testKeypair(t), testKeypair(t)
	z := newE2ESealer()
	now := time.Now()
	s1, _, _ := z.state(a, nil, b.pub, nil, now)
	s2, _, _ := z.state(a, nil, b.pub, nil, now.Add(time.Second))
	s3, _, _ := z.state(a, nil, b.pub, nil, now.Add(e2eRotate+time.Second))
	if s1 != s2 {
		t.Error("key rotated too early")
	}
	if s3 == s1 || s3.eph == s1.eph {
		t.Error("key did not rotate")
	}
	// A new PQ secret always gets a new ephemeral key.
	pq, _ := testPQPair(t, a, b)
	s4, id, _ := z.state(a, nil, b.pub, pq, now.Add(e2eRotate+2*time.Second))
	if s4 == s3 || id != pq.id {
		t.Error("PQ-keyed state shared with the classical one")
	}
}

func TestE2EOutOfOrderWithinWindow(t *testing.T) {
	a, b := testKeypair(t), testKeypair(t)
	psk := []byte("k")
	now := time.Now()
	pq, bLookup := testPQPair(t, a, b)
	z := newE2ESealer()
	var frames [][]byte
	for i := 0; i < 50; i++ {
		f, _ := z.seal(a, psk, b.pub, ip4("10.22.22.9"), ip4("10.22.22.1"), pq, testIPv4("10.22.22.1", "10.22.22.9", []byte{byte(i)}), now)
		frames = append(frames, f[len(ctlMagic)+1:])
	}
	op := newE2EOpener()
	order := []int{49, 3, 0, 48, 25, 1, 2}
	for _, i := range order {
		if _, _, err := op.open(b, psk, append([]byte(nil), frames[i]...), a.pub, bLookup, now); err != nil {
			t.Fatalf("packet %d refused: %v", i, err)
		}
	}
	for _, i := range order {
		if _, _, err := op.open(b, psk, append([]byte(nil), frames[i]...), a.pub, bLookup, now); err != errE2EReplay {
			t.Fatalf("duplicate of %d accepted", i)
		}
	}
}

func TestE2EWindowMatchesModel(t *testing.T) {
	var w e2eWindow
	seen := map[uint64]bool{}
	var hi uint64
	anySeen := false
	for i := 0; i < 20000; i++ {
		r, _ := rand.Int(rand.Reader, big.NewInt(3000))
		n := r.Uint64() + uint64(i)/2
		want := !seen[n] && (!anySeen || n > hi || hi-n < e2eWindowWords*64)
		if got := w.ok(n); got != want {
			t.Fatalf("step %d n=%d hi=%d: ok=%v want %v", i, n, hi, got, want)
		}
		if want {
			w.mark(n)
			seen[n] = true
			if !anySeen || n > hi {
				hi = n
			}
			anySeen = true
		}
	}
}

func TestE2EForgedFramesDoNotFillTable(t *testing.T) {
	b, eve := testKeypair(t), testKeypair(t)
	op := newE2EOpener()
	now := time.Now()
	for i := 0; i < 50; i++ {
		body := make([]byte, e2eHeaderLen+40)
		body[e2eOffVer] = e2eVersion
		rand.Read(body[e2eOffSender : e2eOffSender+32])
		rand.Read(body[e2eOffEph : e2eOffEph+32])
		binary.BigEndian.PutUint32(body[e2eOffTS:], uint32(now.Unix()))
		op.open(b, nil, body, eve.pub, noPQLookup, now)
	}
	if len(op.m) != 0 {
		t.Fatalf("forged frames created %d receive states", len(op.m))
	}
}

// --- ML-KEM exchange unit tests ----------------------------------------------------

func TestE2EPQExchangeAndRetry(t *testing.T) {
	a, b := testKeypair(t), testKeypair(t)
	aPQ, bPQ := newE2EPQ(), newE2EPQ()
	now := time.Now()
	_, offer1 := aPQ.outbound(b.pub, now)
	if offer1 == nil {
		t.Fatal("no offer")
	}
	// Within the retry interval: no duplicate offer.
	if _, o := aPQ.outbound(b.pub, now.Add(100*time.Millisecond)); o != nil {
		t.Fatal("offer retransmitted too soon")
	}
	// After it: the SAME key is offered again.
	_, offer2 := aPQ.outbound(b.pub, now.Add(e2ePQRetry+time.Millisecond))
	if !bytes.Equal(offer1, offer2) {
		t.Fatal("retransmit used a different key")
	}
	r1, _ := bPQ.onOffer(a.pub, offer1[1:], now)
	r2, _ := bPQ.onOffer(a.pub, offer2[1:], now)
	if !bytes.Equal(r1, r2) {
		t.Fatal("duplicate offer got a different reply")
	}
	// A reply for another offer is refused.
	bogus := append([]byte(nil), r1[1:]...)
	bogus[0] ^= 1
	if aPQ.onReply(b.pub, bogus, now) == nil {
		t.Fatal("mismatched reply accepted")
	}
	if err := aPQ.onReply(b.pub, r1[1:], now); err != nil {
		t.Fatal(err)
	}
	sec, _ := aPQ.outbound(b.pub, now)
	if sec == nil || bPQ.secretFor(a.pub, sec.id, now) == nil || *bPQ.secretFor(a.pub, sec.id, now) != sec.ss {
		t.Fatal("the two ends do not hold the same secret")
	}
	// The secret is directional: B has nothing to send to A with.
	if s, _ := bPQ.outbound(a.pub, now); s != nil {
		t.Fatal("B unexpectedly holds an outbound secret")
	}
	// A replayed reply after completion is ignored.
	if aPQ.onReply(b.pub, r1[1:], now) == nil {
		t.Fatal("stale reply accepted")
	}
}

func TestE2EPQRekeyResetAndLimits(t *testing.T) {
	a, b := testKeypair(t), testKeypair(t)
	aPQ, bPQ := newE2EPQ(), newE2EPQ()
	first := testPQExchange(t, aPQ, bPQ, a.pub, b.pub)
	now := time.Now()

	// Rekey: after e2ePQRekey the old secret keeps working while an offer goes out.
	later := now.Add(e2ePQRekey + time.Second)
	cur, offer := aPQ.outbound(b.pub, later)
	if cur != first || offer == nil {
		t.Fatal("rekey should offer while keeping the current secret")
	}
	reply, err := bPQ.onOffer(a.pub, offer[1:], later)
	if err != nil {
		t.Fatal(err)
	}
	if err := aPQ.onReply(b.pub, reply[1:], later); err != nil {
		t.Fatal(err)
	}
	second, _ := aPQ.outbound(b.pub, later)
	if second == first {
		t.Fatal("rekey did not install a new secret")
	}
	// B still accepts the old one briefly, then not.
	if bPQ.secretFor(a.pub, first.id, later.Add(time.Minute)) == nil {
		t.Fatal("previous secret rejected immediately")
	}
	if bPQ.secretFor(a.pub, first.id, later.Add(e2ePQKeepOld+time.Minute)) != nil {
		t.Fatal("previous secret accepted forever")
	}

	// Reset: B lost the secret; A drops it and offers again.
	aPQ.onReset(b.pub, [4]byte{9, 9, 9, 9}) // unknown id: ignored
	if s, _ := aPQ.outbound(b.pub, later); s != second {
		t.Fatal("reset with a foreign id dropped the secret")
	}
	aPQ.onReset(b.pub, second.id)
	if s, o := aPQ.outbound(b.pub, later); s != nil || o == nil {
		t.Fatal("reset did not force a new exchange")
	}
	if !bPQ.shouldReset(a.pub, now) || bPQ.shouldReset(a.pub, now) {
		t.Fatal("reset rate limit wrong")
	}

	// Offer flood from one sender is limited.
	c := newE2EPQ()
	limited := false
	for i := 0; i < e2ePQOffersPerMin+2; i++ {
		o := newE2EPQ()
		_, off := o.outbound(b.pub, now)
		if _, err := c.onOffer(a.pub, off[1:], now); err == errE2EPQLimit {
			limited = true
		}
	}
	if !limited {
		t.Fatal("offer rate limit not enforced")
	}
	// Garbage offers are refused.
	if _, err := newE2EPQ().onOffer(a.pub, []byte{1, 2, 3}, now); err == nil {
		t.Fatal("short offer accepted")
	}
}

func TestIPBindingDerivedOwnershipMobile(t *testing.T) {
	oldCIDR, oldNet := overlayCIDR, overlayNet
	t.Cleanup(func() { overlayCIDR, overlayNet = oldCIDR, oldNet; ipBindings = newIPBindingTable() })
	overlayCIDR = "10.22.0.0/16"
	_, n, _ := net.ParseCIDR(overlayCIDR)
	overlayNet = n
	ipBindings = newIPBindingTable()
	a, b := testKeypair(t), testKeypair(t)
	d, _ := deriveOverlayIPSalted(overlayCIDR, a.pub, 0)
	aIP := stripMask(d)
	if !ipBindings.OwnedBy(a.pub, aIP, true) {
		t.Fatal("a must own its derived address")
	}
	if ipBindings.OwnedBy(b.pub, aIP, true) {
		t.Fatal("b must not own a's address")
	}
}
