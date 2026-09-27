package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

// --- helpers -----------------------------------------------------------------

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

func testDerivedIP(t *testing.T, pub [32]byte) string {
	t.Helper()
	a, err := deriveOverlayIPSalted(overlayCIDR, pub, 0)
	if err != nil {
		t.Fatal(err)
	}
	return stripMask(a)
}

// testIPv4 builds a minimal IPv4 header + payload.
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

type captureTUN struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (c *captureTUN) Read([]byte) (int, error) { return 0, io.EOF }
func (c *captureTUN) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pkts = append(c.pkts, append([]byte(nil), b...))
	return len(b), nil
}
func (c *captureTUN) Close() error { return nil }
func (c *captureTUN) got() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pkts
}

// testSessionPair runs a real in-memory Noise XX handshake and returns the two
// ends' sessions (a's view of b, b's view of a).
func testSessionPair(t *testing.T, a, b keypair, aAddr, bAddr *net.UDPAddr) (aSide, bSide *session) {
	t.Helper()
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	hi, err := noise.NewHandshakeState(noise.Config{CipherSuite: cs, Pattern: noise.HandshakeXX, Initiator: true,
		StaticKeypair: noise.DHKey{Private: a.priv[:], Public: a.pub[:]}})
	if err != nil {
		t.Fatal(err)
	}
	hr, err := noise.NewHandshakeState(noise.Config{CipherSuite: cs, Pattern: noise.HandshakeXX,
		StaticKeypair: noise.DHKey{Private: b.priv[:], Public: b.pub[:]}})
	if err != nil {
		t.Fatal(err)
	}
	m1, _, _, _ := hi.WriteMessage(nil, nil)
	if _, _, _, err := hr.ReadMessage(nil, m1); err != nil {
		t.Fatal(err)
	}
	m2, _, _, _ := hr.WriteMessage(nil, nil)
	if _, _, _, err := hi.ReadMessage(nil, m2); err != nil {
		t.Fatal(err)
	}
	m3, ic1, ic2, _ := hi.WriteMessage(nil, nil)
	_, rc1, rc2, err := hr.ReadMessage(nil, m3)
	if err != nil {
		t.Fatal(err)
	}
	aSide = &session{addr: bAddr, send: ic1, recv: ic2, established: true, peerStatic: b.pub, lastSeen: time.Now(), createdAt: time.Now()}
	bSide = &session{addr: aAddr, send: rc2, recv: rc1, established: true, peerStatic: a.pub, lastSeen: time.Now(), createdAt: time.Now(), initiator: false}
	return aSide, bSide
}

// testPeerSession is an established session (with real cipher states) from
// self to peer at addr.
func testPeerSession(t *testing.T, self, peer keypair, addr *net.UDPAddr) *session {
	t.Helper()
	s, _ := testSessionPair(t, self, peer, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, addr)
	return s
}

// testNode swaps the process-wide node state to `self` for one test.
func testNode(t *testing.T, self keypair, psk []byte) *captureTUN {
	t.Helper()
	oldKP, oldPSK, oldTUN := gKP, gPSK, tunIF
	oldSessions, oldLearn, oldCIDR, oldNet := GlobalSessions, ipLearning, overlayCIDR, overlayNet
	oldIP, oldConn, oldMode := myOverlayIP(), GlobalConn, ipBindingModeSetting
	oldUseExit := usingExit()
	t.Cleanup(func() {
		ipConflictMu.Lock()
		ipConflictLast = nil
		ipConflictMu.Unlock()
		gKP, gPSK, tunIF = oldKP, oldPSK, oldTUN
		GlobalSessions, ipLearning, overlayCIDR, overlayNet = oldSessions, oldLearn, oldCIDR, oldNet
		setMyOverlayIP(oldIP)
		GlobalConn, ipBindingModeSetting = oldConn, oldMode
		useExitFlag.Store(oldUseExit)
		ipBindings = newIPBindingTable()
		e2eSender, e2eReceiver, e2ePQState = newE2ESealer(), newE2EOpener(), newE2EPQ()
		rosterMu.Lock()
		rosterNodes = map[string]rosterView{}
		rosterMu.Unlock()
	})
	e2eRosterPushOff.Store(true)
	gKP, gPSK = self, psk
	cap := &captureTUN{}
	tunIF = cap
	GlobalSessions = NewSessionTable(nil)
	ipLearning = NewIPLearningTable()
	overlayCIDR = "10.22.0.0/16" // wide, so random test keys never collide
	_, n, _ := net.ParseCIDR(overlayCIDR)
	overlayNet = n
	ipBindings = newIPBindingTable()
	e2eSender, e2eReceiver, e2ePQState = newE2ESealer(), newE2EOpener(), newE2EPQ()
	ipBindingModeSetting = ipBindingStrict
	provisions.mu.Lock()
	provisions.recs = map[[32]byte]SignedProvision{}
	provisions.mu.Unlock()
	rosterMu.Lock()
	rosterNodes = map[string]rosterView{}
	rosterMu.Unlock()
	setMyOverlayIP(testDerivedIP(t, self.pub))
	return cap
}

func udpListen(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// readFrame receives one datagram on c and decrypts it with sess (the
// receiving end's session), returning the plaintext payload.
func readFrame(t *testing.T, c *net.UDPConn, sess *session) []byte {
	t.Helper()
	buf := make([]byte, 65535)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no datagram: %v", err)
	}
	if buf[0] != PktData {
		t.Fatalf("unexpected packet type %d", buf[0])
	}
	pt, err := recvPacket(sess, buf[1:n])
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return append([]byte(nil), pt...)
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

// --- node-level tests ---------------------------------------------------------------

// remote is an off-process node's crypto state, for talking to the node under
// test the way a real peer would.
type remote struct {
	kp     keypair
	ip     string
	sealer *e2eSealer
	opener *e2eOpener
	pq     *e2ePQ
}

func newRemote(t *testing.T) *remote {
	kp := testKeypair(t)
	return &remote{kp: kp, ip: testDerivedIP(t, kp.pub), sealer: newE2ESealer(), opener: newE2EOpener(), pq: newE2EPQ()}
}

func (r *remote) seal(t *testing.T, psk []byte, to [32]byte, dstIP string, pq *e2ePQSecret, payload []byte) []byte {
	t.Helper()
	f, err := r.sealer.seal(r.kp, psk, to, ip4(dstIP), ip4(r.ip), pq, payload, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// open decrypts a frame (full payload with ctlMagic) addressed to this remote.
func (r *remote) open(t *testing.T, psk []byte, frame []byte) (e2eHeader, []byte) {
	t.Helper()
	if !bytes.HasPrefix(frame, append(append([]byte(nil), ctlMagic...), e2eFrameType)) {
		t.Fatalf("not a sealed frame: %q", frame[:min(len(frame), 12)])
	}
	h, pt, err := r.opener.open(r.kp, psk, append([]byte(nil), frame[len(ctlMagic)+1:]...), [32]byte{}, lookupIn(r.pq), time.Now())
	if err != nil {
		t.Fatalf("remote could not open: %v", err)
	}
	return h, pt
}

// relayLink wires the node under test to a fake relay R over a real UDP
// socket with real Noise sessions; frames the node sends to R can be read.
type relayLink struct {
	kp       keypair
	addr     *net.UDPAddr
	conn     *net.UDPConn
	fromNode *session
}

func newRelayLink(t *testing.T) *relayLink {
	t.Helper()
	nodeConn := udpListen(t)
	GlobalConn = nodeConn
	rc := udpListen(t)
	l := &relayLink{kp: testKeypair(t), conn: rc, addr: rc.LocalAddr().(*net.UDPAddr)}
	toR, fromNode := testSessionPair(t, gKP, l.kp, nodeConn.LocalAddr().(*net.UDPAddr), l.addr)
	l.fromNode = fromNode
	GlobalSessions.set(l.addr, toR)
	return l
}

func (l *relayLink) read(t *testing.T) []byte { t.Helper(); return readFrame(t, l.conn, l.fromNode) }

// The full relayed flow at the destination: A's offer is answered through the
// relay, then A's PQ-sealed data is delivered and the return route learned.
func TestE2EDestinationFullExchange(t *testing.T) {
	psk := []byte("psk")
	b := testKeypair(t)
	tun := testNode(t, b, psk)
	bIP := myOverlayIP()
	rl := newRelayLink(t)
	a := newRemote(t)

	// 1. offer
	_, offer := a.pq.outbound(b.pub, time.Now())
	handleControl(a.seal(t, psk, b.pub, bIP, nil, offer)[len(ctlMagic):], rl.addr)
	// 2. B's reply comes back out through the relay, sealed to A.
	h, reply := a.open(t, psk, rl.read(t))
	if h.hasPQ() || net.IP(h.dst[:]).String() != a.ip || reply[0] != e2eKindReply {
		t.Fatal("unexpected reply frame")
	}
	if err := a.pq.onReply(b.pub, reply[1:], time.Now()); err != nil {
		t.Fatal(err)
	}
	sec, _ := a.pq.outbound(b.pub, time.Now())
	if sec == nil {
		t.Fatal("A has no secret")
	}
	// 3. data
	pkt := testIPv4(a.ip, bIP, []byte("secret"))
	handleControl(a.seal(t, psk, b.pub, bIP, sec, pkt)[len(ctlMagic):], rl.addr)
	got := tun.got()
	if len(got) != 1 || !bytes.Equal(got[0], pkt) {
		t.Fatalf("expected the packet delivered once, got %d", len(got))
	}
	if l := ipLearning.Lookup(a.ip); l == nil || l.String() != rl.addr.String() {
		t.Fatalf("return route to %s not learned via relay: %v", a.ip, l)
	}
}

// Relayed data sealed without an ML-KEM secret is refused, and data under a
// secret the node does not hold triggers a reset to the sender.
func TestE2EDestinationRequiresPQ(t *testing.T) {
	psk := []byte("psk")
	b := testKeypair(t)
	tun := testNode(t, b, psk)
	bIP := myOverlayIP()
	rl := newRelayLink(t)
	a := newRemote(t)

	pkt := testIPv4(a.ip, bIP, []byte("classical"))
	handleControl(a.seal(t, psk, b.pub, bIP, nil, pkt)[len(ctlMagic):], rl.addr)
	if len(tun.got()) != 0 {
		t.Fatal("relayed data without ML-KEM was delivered")
	}

	// A believes it has a secret B never heard of (B restarted).
	other := newE2EPQ()
	stale := testPQExchange(t, a.pq, other, a.kp.pub, b.pub)
	handleControl(a.seal(t, psk, b.pub, bIP, stale, pkt)[len(ctlMagic):], rl.addr)
	if len(tun.got()) != 0 {
		t.Fatal("data under an unknown secret was delivered")
	}
	_, reset := a.open(t, psk, rl.read(t))
	if len(reset) != 5 || reset[0] != e2eKindReset || [4]byte(reset[1:]) != stale.id {
		t.Fatalf("expected a reset for the stale secret, got %x", reset)
	}
	a.pq.onReset(b.pub, stale.id)
	if s, o := a.pq.outbound(b.pub, time.Now()); s != nil || o == nil {
		t.Fatal("A did not restart the exchange")
	}
}

// A sender cannot use an overlay source address its key does not own, even
// inside a correctly sealed frame.
func TestE2EDestinationRejectsSpoofedSource(t *testing.T) {
	psk := []byte("psk")
	b := testKeypair(t)
	tun := testNode(t, b, psk)
	bIP := myOverlayIP()
	rl := newRelayLink(t)
	a, victim := newRemote(t), newRemote(t)
	a.ip = victim.ip // A claims the victim's address in the header

	_, offer := a.pq.outbound(b.pub, time.Now())
	handleControl(a.seal(t, psk, b.pub, bIP, nil, offer)[len(ctlMagic):], rl.addr)
	_ = rl.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _, err := rl.conn.ReadFromUDP(make([]byte, 2048)); err == nil {
		t.Fatalf("B answered an offer from a spoofed source (%d bytes)", n)
	}
	if ipLearning.Lookup(victim.ip) != nil {
		t.Fatal("victim's address was re-routed to the relay")
	}
	// Even with a secret (obtained any way), spoofed data is dropped.
	bPQ := e2ePQState
	sec := testPQExchange(t, newE2EPQ(), bPQ, a.kp.pub, b.pub)
	handleControl(a.seal(t, psk, b.pub, bIP, sec, testIPv4(victim.ip, bIP, []byte("spoof")))[len(ctlMagic):], rl.addr)
	if n := len(tun.got()); n != 0 {
		t.Fatalf("spoofed-source packet delivered (%d)", n)
	}
}

// Inner and outer source must agree.
func TestE2EDestinationRejectsMismatchedInnerSource(t *testing.T) {
	psk := []byte("psk")
	b := testKeypair(t)
	tun := testNode(t, b, psk)
	bIP := myOverlayIP()
	rl := newRelayLink(t)
	a, victim := newRemote(t), newRemote(t)
	sec := testPQExchange(t, a.pq, e2ePQState, a.kp.pub, b.pub)
	handleControl(a.seal(t, psk, b.pub, bIP, sec, testIPv4(victim.ip, bIP, []byte("x")))[len(ctlMagic):], rl.addr)
	if len(tun.got()) != 0 {
		t.Fatal("inner source differing from the authenticated one was delivered")
	}
}

// The old plaintext 'R' frame is no longer delivered or forwarded.
func TestLegacyPlaintextRelayRefused(t *testing.T) {
	a, r, b := testKeypair(t), testKeypair(t), testKeypair(t)
	tun := testNode(t, b, nil)
	rAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40003}
	GlobalSessions.set(rAddr, testPeerSession(t, gKP, r, rAddr))
	pkt := testIPv4(testDerivedIP(t, a.pub), testDerivedIP(t, b.pub), []byte("x"))
	handleControl(append([]byte{'R'}, pkt...), rAddr)
	if len(tun.got()) != 0 {
		t.Fatal("legacy plaintext relay frame was delivered")
	}
}

// Relay role: the frame is forwarded unchanged except for the hop counter, only
// to the destination's own session, and the relay cannot read it.
func TestE2ERelayForwardsCiphertextOnly(t *testing.T) {
	psk := []byte("psk")
	r := testKeypair(t)
	testNode(t, r, psk)
	relayConn := udpListen(t)
	bConn := udpListen(t)
	GlobalConn = relayConn
	a, bRemote := newRemote(t), newRemote(t)
	b := bRemote.kp
	aAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40004}
	bAddr := bConn.LocalAddr().(*net.UDPAddr)

	GlobalSessions.set(aAddr, testPeerSession(t, gKP, a.kp, aAddr))
	rToB, bFromR := testSessionPair(t, r, b, relayConn.LocalAddr().(*net.UDPAddr), bAddr)
	GlobalSessions.set(bAddr, rToB)
	bIP := bRemote.ip
	ipLearning.Learn(bIP, bAddr)
	setPeerOverlayIP(b.pub, bIP) // B announced its address on its session
	t.Cleanup(func() { nameMu.Lock(); delete(peerOverlayIPs, b.pub); nameMu.Unlock() })

	sec := testPQExchange(t, a.pq, bRemote.pq, a.kp.pub, b.pub)
	pkt := testIPv4(a.ip, bIP, []byte("for B only"))
	frame := a.seal(t, psk, b.pub, bIP, sec, pkt)
	handleControl(append([]byte(nil), frame[len(ctlMagic):]...), aAddr)

	fwd := readFrame(t, bConn, bFromR)
	if bytes.Contains(fwd, []byte("for B only")) {
		t.Fatal("plaintext visible to the relay")
	}
	if fwd[len(ctlMagic)+1+e2eOffHop] != 1 {
		t.Fatal("hop counter not set by the relay")
	}
	if _, _, err := newE2EOpener().open(r, psk, append([]byte(nil), fwd[len(ctlMagic)+1:]...), a.kp.pub, lookupIn(e2ePQState), time.Now()); err == nil {
		t.Fatal("the relay could open the frame")
	}
	if _, pt := bRemote.open(t, psk, fwd); !bytes.Equal(pt, pkt) {
		t.Fatal("destination got different plaintext")
	}

	// A frame that already made its hop is not forwarded again.
	again := a.seal(t, psk, b.pub, bIP, sec, pkt)
	again[len(ctlMagic)+1+e2eOffHop] = 1
	before := statE2EDropRoute.Load()
	handleControl(again[len(ctlMagic):], aAddr)
	if statE2EDropRoute.Load() != before+1 {
		t.Fatal("second hop was not refused")
	}
}

// Relay role: a next hop whose key does not own the destination is not used.
func TestE2ERelayOnlyForwardsToOwner(t *testing.T) {
	psk := []byte("psk")
	r := testKeypair(t)
	testNode(t, r, psk)
	relayConn := udpListen(t)
	mConn := udpListen(t)
	GlobalConn = relayConn
	a, b, mallory := newRemote(t), newRemote(t), testKeypair(t)
	aAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40005}
	mAddr := mConn.LocalAddr().(*net.UDPAddr)
	GlobalSessions.set(aAddr, testPeerSession(t, gKP, a.kp, aAddr))
	rToM, _ := testSessionPair(t, r, mallory, relayConn.LocalAddr().(*net.UDPAddr), mAddr)
	GlobalSessions.set(mAddr, rToM)
	ipLearning.Learn(b.ip, mAddr) // poisoned route

	sec := testPQExchange(t, a.pq, b.pq, a.kp.pub, b.kp.pub)
	before := statE2EDropRoute.Load()
	handleControl(a.seal(t, psk, b.kp.pub, b.ip, sec, testIPv4(a.ip, b.ip, []byte("x")))[len(ctlMagic):], aAddr)
	if statE2EDropRoute.Load() != before+1 {
		t.Fatal("frame forwarded to a session that does not own the destination")
	}
}

// Sender role, end to end: the first packet to a relayed destination starts
// the ML-KEM exchange and is not sent; once the reply arrives, packets leave
// PQ-sealed; packets to the relay itself leave raw.
func TestSenderRelayedFlow(t *testing.T) {
	psk := []byte("psk")
	a := testKeypair(t)
	testNode(t, a, psk)
	aIP := myOverlayIP()
	rl := newRelayLink(t)
	b := newRemote(t)
	rosterMu.Lock()
	rosterNodes[b.ip] = rosterView{rosterEntry: rosterEntry{IP: b.ip, PK: base64.StdEncoding.EncodeToString(b.kp.pub[:])}, Seen: time.Now()}
	rosterMu.Unlock()
	rSess := GlobalSessions.GetByAddr(rl.addr)
	ipLearning.Learn(b.ip, rl.addr) // route to B via the relay

	pkt := testIPv4(aIP, b.ip, []byte("via relay"))
	sent, err := sendOverlayViaSession(GlobalConn, rl.addr, rSess, pkt, b.ip)
	if err != nil || sent {
		t.Fatalf("first packet must wait for the ML-KEM exchange (sent=%v err=%v)", sent, err)
	}
	h, offer := b.open(t, psk, rl.read(t))
	if h.hasPQ() || offer[0] != e2eKindOffer || net.IP(h.src[:]).String() != aIP {
		t.Fatal("expected a classical offer from A")
	}
	reply, err := b.pq.onOffer(a.pub, offer[1:], time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handleControl(b.seal(t, psk, a.pub, aIP, nil, reply)[len(ctlMagic):], rl.addr)
	if statE2EPQExchanges.Load() == 0 {
		t.Fatal("A did not complete the exchange")
	}

	sent, err = sendOverlayViaSession(GlobalConn, rl.addr, rSess, pkt, b.ip)
	if err != nil || !sent {
		t.Fatalf("not sent after the exchange: %v", err)
	}
	wire := rl.read(t)
	if bytes.Contains(wire, []byte("via relay")) {
		t.Fatal("packet to a relay was not sealed")
	}
	h, pt := b.open(t, psk, wire)
	if !h.hasPQ() || !bytes.Equal(pt, pkt) {
		t.Fatal("relayed data not PQ-sealed or altered")
	}

	// Direct to the relay itself (which announced its address): raw.
	rIP := testDerivedIP(t, rl.kp.pub)
	setPeerOverlayIP(rl.kp.pub, rIP)
	direct := testIPv4(aIP, rIP, []byte("direct"))
	if sent, err := sendOverlayViaSession(GlobalConn, rl.addr, rSess, direct, rIP); err != nil || !sent {
		t.Fatalf("direct not sent: %v", err)
	}
	if got := rl.read(t); !bytes.Equal(got, direct) {
		t.Fatal("direct packet altered")
	}

	// Unknown destination key: nothing is sent at all.
	other := testDerivedIP(t, testKeypair(t).pub)
	if sent, _ := sendOverlayViaSession(GlobalConn, rl.addr, rSess, testIPv4(aIP, other, nil), other); sent {
		t.Fatal("sent a packet with no verifiable destination key")
	}
	// A packet not sourced from our own address is never relayed.
	if sent, _ := sendOverlayViaSession(GlobalConn, rl.addr, rSess, testIPv4("8.8.8.8", b.ip, nil), b.ip); sent {
		t.Fatal("relayed a packet with a foreign source")
	}
}

// A roster entry lying about who owns a derived address is ignored.
func TestOwnerOfIgnoresLyingRoster(t *testing.T) {
	self, b, mallory := testKeypair(t), testKeypair(t), testKeypair(t)
	testNode(t, self, nil)
	bIP := testDerivedIP(t, b.pub)
	rosterMu.Lock()
	rosterNodes[bIP] = rosterView{rosterEntry: rosterEntry{IP: bIP, PK: base64.StdEncoding.EncodeToString(mallory.pub[:])}, Seen: time.Now()}
	rosterMu.Unlock()
	if k, ok := ipBindings.OwnerOf(bIP); ok && k == mallory.pub {
		t.Fatal("roster lie redirected sealing to the liar")
	}
}
