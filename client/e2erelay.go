package main

// e2erelay.go — end-to-end encryption for traffic that crosses a relay.
//
// THE BUG THIS CLOSES
//
// Each Noise session only protects ONE hop. When a packet had no direct route,
// the sender wrapped the raw IPv4 packet in an 'R' control frame and flooded it
// to every direct peer; each of those peers decrypted the hop, read the packet
// in the clear, and forwarded it — again in the clear inside the next hop's
// tunnel. Return traffic was forwarded the same way. Every node in the mesh
// could therefore read (and, before ip-binding, rewrite) other nodes' relayed
// traffic.
//
// THE FIX
//
// Relayed packets are sealed by the SENDER for the DESTINATION node, and only
// the destination can open them:
//
//	OVLYCTL1 Z | ver | hop | dst(4) | src(4) | sender(32) | eph(32) | ts(4) | ctr(8) | pqid(4) | AEAD(payload)
//
// A relay reads the destination address (to pick the next hop) and the hop
// counter. Everything else is authenticated, and the payload is opaque. (The
// source address and sender key are not secret from a relay — it can see
// which of its peers handed it the frame — and are carried so the destination
// can route replies and resets.)
//
// KEYS. Every envelope key combines three independent secrets:
//
//	key = HKDF-SHA256(salt   = H(network PSK),
//	                  secret = DH(eph, B) || DH(A, B) || ML-KEM secret,
//	                  info   = label || A || B || eph || pqid)
//
//   - DH(eph, B): only B's static private key opens it — relays see
//     ciphertext. The sender's ephemeral key rotates every e2eRotate, so every
//     epoch has a fresh key and the counter nonce can never repeat, even
//     across restarts.
//   - DH(A, B): authenticates the sender. Nobody without A's (or B's) static
//     private key can make a packet that opens as "from A"; the destination
//     then checks A owns the packet's source address (ipbinding.go).
//   - ML-KEM-768 secret (e2epq.go): established end-to-end between A and B,
//     so a future quantum computer that breaks X25519 still cannot read
//     recorded relayed traffic. Relayed DATA is only ever sealed with it —
//     there is no classical fallback. Only the ML-KEM exchange messages
//     themselves use a classical envelope (pqid 0); they carry public values.
//   - The PSK salt additionally requires the network secret.
//
// Replays are rejected per key with a sliding window; keys older than
// e2eMaxSkew are refused, and receive state is kept longer than that, so a
// captured packet cannot be replayed after its window is forgotten. Receive
// state is only created for a packet that authenticates.

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	e2eFrameType = 'Z'
	e2eVersion   = 1

	// Offsets within the frame body that follows ctlMagic+'Z'.
	e2eOffVer    = 0
	e2eOffHop    = 1
	e2eOffDst    = 2
	e2eOffSrc    = 6
	e2eOffSender = 10
	e2eOffEph    = 42
	e2eOffTS     = 74
	e2eOffCtr    = 78
	e2eOffPQID   = 86
	e2eHeaderLen = 90

	// e2eOverhead is what a relayed packet costs over a direct one, on top of
	// the 9-byte control prefix.
	e2eOverhead = e2eHeaderLen + chacha20poly1305.Overhead

	e2eRotate        = 2 * time.Minute
	e2eMaxPackets    = 1 << 32
	e2eMaxSkew       = 15 * time.Minute
	e2eRecvKeep      = 2*e2eMaxSkew + e2eRotate + 5*time.Minute
	e2eMaxSendKeys   = 1024
	e2eMaxRecvKeys   = 8192
	e2eNewKeysPerSec = 200
	e2eWindowWords   = 16 // 1024-packet replay window: flooded copies arrive out of order
)

var e2eLabel = []byte("apgo-e2e-relay-v1")

var (
	errE2EShort   = errors.New("e2e: short frame")
	errE2EVersion = errors.New("e2e: unknown version")
	errE2EStale   = errors.New("e2e: key timestamp outside the accepted window")
	errE2ELimit   = errors.New("e2e: key-derivation rate limit")
	errE2EAuth    = errors.New("e2e: authentication failed")
	errE2EReplay  = errors.New("e2e: replayed or too-old packet")
	errE2ENoPQ    = errors.New("e2e: unknown post-quantum secret")
)

func e2eSalt(psk []byte) []byte {
	h := sha256.Sum256(append([]byte("OVLY-E2E-PSK-1:"), psk...))
	return h[:]
}

// e2eDeriveAEAD derives the envelope key. pqss is nil for a classical
// (key-exchange-only) envelope, whose pqid is zero.
func e2eDeriveAEAD(dh1, dh2, pqss, psk []byte, sender, recipient, eph [32]byte, pqid [4]byte) (cipher.AEAD, error) {
	secret := make([]byte, 0, len(dh1)+len(dh2)+len(pqss))
	secret = append(append(append(secret, dh1...), dh2...), pqss...)
	info := make([]byte, 0, len(e2eLabel)+100)
	info = append(info, e2eLabel...)
	info = append(info, sender[:]...)
	info = append(info, recipient[:]...)
	info = append(info, eph[:]...)
	info = append(info, pqid[:]...)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, e2eSalt(psk), info), key); err != nil {
		return nil, err
	}
	return chacha20poly1305.New(key)
}

// e2eAD is the authenticated header: everything except the hop counter, which
// the relay is allowed to change.
func e2eAD(hdr []byte) [e2eHeaderLen]byte {
	var ad [e2eHeaderLen]byte
	copy(ad[:], hdr[:e2eHeaderLen])
	ad[e2eOffHop] = 0
	return ad
}

func e2eNonce(ctr uint64) [chacha20poly1305.NonceSize]byte {
	var n [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n
}

// --- sender -----------------------------------------------------------------

type e2eSendKey struct {
	to   [32]byte
	pqid [4]byte
}

type e2eSendState struct {
	eph  [32]byte
	ts   uint32
	born time.Time
	aead cipher.AEAD
	ctr  atomic.Uint64
}

type e2eSealer struct {
	mu sync.Mutex
	m  map[e2eSendKey]*e2eSendState
}

func newE2ESealer() *e2eSealer { return &e2eSealer{m: map[e2eSendKey]*e2eSendState{}} }

func (z *e2eSealer) state(self keypair, psk []byte, to [32]byte, pq *e2ePQSecret, now time.Time) (*e2eSendState, [4]byte, error) {
	var pqid [4]byte
	var pqss []byte
	if pq != nil {
		pqid, pqss = pq.id, pq.ss[:]
	}
	k := e2eSendKey{to, pqid}
	z.mu.Lock()
	defer z.mu.Unlock()
	if st := z.m[k]; st != nil && now.Sub(st.born) < e2eRotate && st.ctr.Load() < e2eMaxPackets {
		return st, pqid, nil
	}
	var ephPriv [32]byte
	if _, err := rand.Read(ephPriv[:]); err != nil {
		return nil, pqid, err
	}
	ephPub, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, pqid, err
	}
	dh1, err := curve25519.X25519(ephPriv[:], to[:])
	if err != nil {
		return nil, pqid, err // low-order recipient key
	}
	dh2, err := curve25519.X25519(self.priv[:], to[:])
	if err != nil {
		return nil, pqid, err
	}
	st := &e2eSendState{ts: uint32(now.Unix()), born: now}
	copy(st.eph[:], ephPub)
	if st.aead, err = e2eDeriveAEAD(dh1, dh2, pqss, psk, self.pub, to, st.eph, pqid); err != nil {
		return nil, pqid, err
	}
	if len(z.m) >= e2eMaxSendKeys {
		for kk, v := range z.m {
			if now.Sub(v.born) >= e2eRotate {
				delete(z.m, kk)
			}
		}
		if len(z.m) >= e2eMaxSendKeys {
			for kk := range z.m { // still full: drop an arbitrary entry
				delete(z.m, kk)
				break
			}
		}
	}
	z.m[k] = st
	return st, pqid, nil
}

// seal returns the full control payload (ctlMagic + 'Z' + header + ciphertext)
// carrying payload from self (at overlay address src) to the node whose
// static key is `to` (at dst). pq must be non-nil for data.
func (z *e2eSealer) seal(self keypair, psk []byte, to [32]byte, dst, src [4]byte, pq *e2ePQSecret, payload []byte, now time.Time) ([]byte, error) {
	st, pqid, err := z.state(self, psk, to, pq, now)
	if err != nil {
		return nil, err
	}
	ctr := st.ctr.Add(1)
	out := make([]byte, 0, len(ctlMagic)+1+e2eHeaderLen+len(payload)+chacha20poly1305.Overhead)
	out = append(out, ctlMagic...)
	out = append(out, e2eFrameType)
	h := len(out)
	out = out[:h+e2eHeaderLen]
	hdr := out[h:]
	hdr[e2eOffVer] = e2eVersion
	hdr[e2eOffHop] = 0
	copy(hdr[e2eOffDst:], dst[:])
	copy(hdr[e2eOffSrc:], src[:])
	copy(hdr[e2eOffSender:], self.pub[:])
	copy(hdr[e2eOffEph:], st.eph[:])
	binary.BigEndian.PutUint32(hdr[e2eOffTS:], st.ts)
	binary.BigEndian.PutUint64(hdr[e2eOffCtr:], ctr)
	copy(hdr[e2eOffPQID:], pqid[:])
	ad := e2eAD(hdr)
	nonce := e2eNonce(ctr)
	return st.aead.Seal(out, nonce[:], payload, ad[:]), nil
}

// --- receiver ---------------------------------------------------------------

type e2eWindow struct {
	any  bool
	hi   uint64
	bits [e2eWindowWords]uint64
}

func (w *e2eWindow) ok(n uint64) bool {
	if !w.any || n > w.hi {
		return true
	}
	d := w.hi - n
	if d >= e2eWindowWords*64 {
		return false
	}
	return w.bits[d/64]&(1<<(d%64)) == 0
}

func (w *e2eWindow) mark(n uint64) {
	if !w.any {
		w.any, w.hi = true, n
		w.bits = [e2eWindowWords]uint64{1}
		return
	}
	if n > w.hi {
		w.shift(n - w.hi)
		w.hi = n
		w.bits[0] |= 1
		return
	}
	if d := w.hi - n; d < e2eWindowWords*64 {
		w.bits[d/64] |= 1 << (d % 64)
	}
}

// shift ages every recorded bit by s positions (bit d -> d+s).
func (w *e2eWindow) shift(s uint64) {
	if s >= e2eWindowWords*64 {
		w.bits = [e2eWindowWords]uint64{}
		return
	}
	ws, bs := int(s/64), s%64
	for j := e2eWindowWords - 1; j >= 0; j-- {
		var v uint64
		if src := j - ws; src >= 0 {
			v = w.bits[src] << bs
			if bs > 0 && src-1 >= 0 {
				v |= w.bits[src-1] >> (64 - bs)
			}
		}
		w.bits[j] = v
	}
}

type e2eRecvKey struct {
	sender, eph [32]byte
	pqid        [4]byte
}

type e2eRecvState struct {
	mu   sync.Mutex
	aead cipher.AEAD
	ts   time.Time
	win  e2eWindow
}

type e2eBucket struct {
	tokens float64
	last   time.Time
}

type e2eOpener struct {
	mu      sync.Mutex
	m       map[e2eRecvKey]*e2eRecvState
	buckets map[[32]byte]*e2eBucket
}

func newE2EOpener() *e2eOpener {
	return &e2eOpener{m: map[e2eRecvKey]*e2eRecvState{}, buckets: map[[32]byte]*e2eBucket{}}
}

type e2eHeader struct {
	hop    byte
	dst    [4]byte
	src    [4]byte
	sender [32]byte
	eph    [32]byte
	ts     uint32
	ctr    uint64
	pqid   [4]byte
}

func (h e2eHeader) hasPQ() bool { return h.pqid != ([4]byte{}) }

// parseE2E splits a frame body (the bytes after 'Z') into header and
// ciphertext. It does not authenticate anything.
func parseE2E(body []byte) (h e2eHeader, ct []byte, err error) {
	if len(body) < e2eHeaderLen+chacha20poly1305.Overhead {
		return h, nil, errE2EShort
	}
	if body[e2eOffVer] != e2eVersion {
		return h, nil, errE2EVersion
	}
	h.hop = body[e2eOffHop]
	copy(h.dst[:], body[e2eOffDst:])
	copy(h.src[:], body[e2eOffSrc:])
	copy(h.sender[:], body[e2eOffSender:])
	copy(h.eph[:], body[e2eOffEph:])
	h.ts = binary.BigEndian.Uint32(body[e2eOffTS:])
	h.ctr = binary.BigEndian.Uint64(body[e2eOffCtr:])
	copy(h.pqid[:], body[e2eOffPQID:])
	return h, body[e2eHeaderLen:], nil
}

// allowDerivation rate-limits NEW key derivations per delivering peer, so one
// misbehaving relay can burn neither this node's CPU nor other relays' budget.
// Caller holds o.mu.
func (o *e2eOpener) allowDerivation(via [32]byte, now time.Time) bool {
	b := o.buckets[via]
	if b == nil {
		if len(o.buckets) >= 1024 {
			o.buckets = map[[32]byte]*e2eBucket{}
		}
		b = &e2eBucket{tokens: e2eNewKeysPerSec, last: now}
		o.buckets[via] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * e2eNewKeysPerSec
	if b.tokens > e2eNewKeysPerSec {
		b.tokens = e2eNewKeysPerSec
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (st *e2eRecvState) openLocked(body, ct []byte, h e2eHeader) ([]byte, error) {
	if !st.win.ok(h.ctr) {
		return nil, errE2EReplay
	}
	ad := e2eAD(body)
	nonce := e2eNonce(h.ctr)
	pt, err := st.aead.Open(ct[:0], nonce[:], ct, ad[:])
	if err != nil {
		return nil, errE2EAuth
	}
	st.win.mark(h.ctr)
	return pt, nil
}

// e2ePQLookup returns the ML-KEM secret `sender` tagged a packet with.
type e2ePQLookup func(sender [32]byte, id [4]byte) *[32]byte

// open authenticates and decrypts a frame body addressed to self. body is the
// bytes after 'Z'; via is the key of the session it arrived on (for rate
// limiting). The plaintext is written over the ciphertext. Receive state is
// only ever created for a packet that authenticates, so forged frames cannot
// fill the table. errE2ENoPQ is returned (with the parsed header) when the
// packet names a post-quantum secret this node does not hold.
func (o *e2eOpener) open(self keypair, psk []byte, body []byte, via [32]byte, pqLookup e2ePQLookup, now time.Time) (e2eHeader, []byte, error) {
	h, ct, err := parseE2E(body)
	if err != nil {
		return h, nil, err
	}
	if h.sender == self.pub {
		return h, nil, errE2EAuth
	}
	ts := time.Unix(int64(h.ts), 0)
	if d := now.Sub(ts); d > e2eMaxSkew || d < -e2eMaxSkew {
		return h, nil, errE2EStale
	}
	k := e2eRecvKey{h.sender, h.eph, h.pqid}

	o.mu.Lock()
	st := o.m[k]
	o.mu.Unlock()
	if st != nil {
		st.mu.Lock()
		defer st.mu.Unlock()
		pt, err := st.openLocked(body, ct, h)
		return h, pt, err
	}

	var pqss []byte
	if h.hasPQ() {
		ss := pqLookup(h.sender, h.pqid)
		if ss == nil {
			return h, nil, errE2ENoPQ
		}
		pqss = ss[:]
	}
	o.mu.Lock()
	allowed := o.allowDerivation(via, now)
	o.mu.Unlock()
	if !allowed {
		return h, nil, errE2ELimit
	}
	dh1, err := curve25519.X25519(self.priv[:], h.eph[:])
	if err != nil {
		return h, nil, errE2EAuth
	}
	dh2, err := curve25519.X25519(self.priv[:], h.sender[:])
	if err != nil {
		return h, nil, errE2EAuth
	}
	aead, err := e2eDeriveAEAD(dh1, dh2, pqss, psk, h.sender, self.pub, h.eph, h.pqid)
	if err != nil {
		return h, nil, err
	}
	fresh := &e2eRecvState{aead: aead, ts: ts}
	pt, err := fresh.openLocked(body, ct, h)
	if err != nil {
		return h, nil, err
	}

	o.mu.Lock()
	if cur := o.m[k]; cur != nil {
		// Another packet of the same key won the race: its window is the
		// authoritative one.
		o.mu.Unlock()
		cur.mu.Lock()
		defer cur.mu.Unlock()
		if !cur.win.ok(h.ctr) {
			return h, nil, errE2EReplay
		}
		cur.win.mark(h.ctr)
		return h, pt, nil
	}
	if len(o.m) >= e2eMaxRecvKeys {
		for kk, v := range o.m {
			if now.Sub(v.ts) > e2eRecvKeep {
				delete(o.m, kk)
			}
		}
		if len(o.m) >= e2eMaxRecvKeys {
			// Without a stored window this packet's replays could not be
			// detected, and evicting a live window would re-open replays for
			// that key. Refuse instead.
			o.mu.Unlock()
			return h, nil, errE2ELimit
		}
	}
	o.m[k] = fresh
	o.mu.Unlock()
	return h, pt, nil
}

func (o *e2eOpener) prune(now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for k, v := range o.m {
		if now.Sub(v.ts) > e2eRecvKeep {
			delete(o.m, k)
		}
	}
}

// --- node glue ----------------------------------------------------------------

var (
	e2eSender   = newE2ESealer()
	e2eReceiver = newE2EOpener()
	e2ePQState  = newE2EPQ()

	statE2ESealed        atomic.Uint64 // relayed packets we sealed
	statE2EOpened        atomic.Uint64 // relayed packets opened and delivered here
	statE2EForwarded     atomic.Uint64 // sealed packets we forwarded for others
	statE2EDropNoKey     atomic.Uint64 // no verifiable key for the destination: not sent
	statE2EDropPQWait    atomic.Uint64 // end-to-end ML-KEM not ready yet: not sent
	statE2EDropAuth      atomic.Uint64 // failed to authenticate / stale / rate-limited
	statE2EDropNoPQ      atomic.Uint64 // named an ML-KEM secret we do not hold (reset sent)
	statE2EDropReplay    atomic.Uint64 // duplicate (normal for flooded copies) or replay
	statE2EDropSource    atomic.Uint64 // source not owned by the sealing key, or malformed
	statE2EDropRoute     atomic.Uint64 // transit frame with no direct route to its owner
	statE2EDropPolicy    atomic.Uint64 // revoked or unapproved sender/destination
	statE2EDropLegacy    atomic.Uint64 // legacy plaintext 'R' relay frame refused
	statE2EPQExchanges   atomic.Uint64 // end-to-end ML-KEM exchanges completed
	statRxDropIPBinding  atomic.Uint64 // claim/packet from a key that does not own the address
	statRxDropExitPolicy atomic.Uint64 // exit-bound packet to a private/non-public destination

	e2eLegacyLogMu   sync.Mutex
	e2eLegacyLogLast time.Time
	e2ePruneOnce     sync.Once
)

func ipv4To4(ip string) ([4]byte, bool) {
	var out [4]byte
	p := net.ParseIP(ip).To4()
	if p == nil {
		return out, false
	}
	copy(out[:], p)
	return out, true
}

func e2ePQSecretLookup(sender [32]byte, id [4]byte) *[32]byte {
	return e2ePQState.secretFor(sender, id, time.Now())
}

func e2eStartPruner() {
	e2ePruneOnce.Do(func() {
		go func() {
			for range time.Tick(time.Minute) {
				e2eReceiver.prune(time.Now())
			}
		}()
	})
}

// e2eSendControl delivers a sealed frame toward dstIP: over the learned route
// if there is one, otherwise to every admitted direct peer (only the owner of
// dstIP can open it).
func e2eSendControl(dstIP string, frame []byte) {
	if GlobalSessions == nil || GlobalConn == nil {
		return
	}
	if a := ipLearning.Lookup(dstIP); a != nil {
		if s := GlobalSessions.GetByAddr(a); s != nil && s.Established() && admissionOK(s.peerStatic, "e2e-ctl") {
			_ = sendPacket(GlobalConn, a, s, frame)
			return
		}
	}
	for _, a := range GlobalSessions.EstablishedAddrs() {
		if s := GlobalSessions.GetByAddr(a); s != nil && s.Established() && admissionOK(s.peerStatic, "e2e-ctl") {
			_ = sendPacket(GlobalConn, a, s, frame)
		}
	}
}

// e2eSealControl seals a key-exchange message (classical envelope) to `to`.
func e2eSealControl(to [32]byte, dstIP string, payload []byte) ([]byte, bool) {
	dst, ok1 := ipv4To4(dstIP)
	src, ok2 := ipv4To4(e2eSelfIP())
	if !ok1 || !ok2 {
		return nil, false
	}
	f, err := e2eSender.seal(gKP, gPSK, to, dst, src, nil, payload, time.Now())
	return f, err == nil
}

// buildE2EFrame seals an IPv4 packet for the overlay node that owns its
// destination. ok=false means the packet must NOT be sent through a relay:
// no verifiable key is known for the destination, or the end-to-end ML-KEM
// exchange with it has not completed yet (it is started here).
func buildE2EFrame(pkt []byte) ([]byte, bool) {
	e2eStartPruner()
	me := e2eSelfIP()
	dstIP, srcIP := extractIPv4Dst(pkt), extractIPv4Src(pkt)
	if me == "" || srcIP != me || dstIP == "" || !inOverlaySubnet(dstIP) {
		return nil, false
	}
	dst, ok1 := ipv4To4(dstIP)
	src, ok2 := ipv4To4(srcIP)
	if !ok1 || !ok2 {
		return nil, false
	}
	owner, ok := ipBindings.OwnerOf(dstIP)
	if !ok {
		statE2EDropNoKey.Add(1)
		return nil, false
	}
	now := time.Now()
	pq, offer := e2ePQState.outbound(owner, now)
	if offer != nil {
		if f, ok := e2eSealControl(owner, dstIP, offer); ok {
			e2eSendControl(dstIP, f)
		}
	}
	if pq == nil {
		statE2EDropPQWait.Add(1)
		return nil, false
	}
	frame, err := e2eSender.seal(gKP, gPSK, owner, dst, src, pq, pkt, now)
	if err != nil {
		statE2EDropNoKey.Add(1)
		return nil, false
	}
	statE2ESealed.Add(1)
	return frame, true
}

// handleE2EFrame processes an 'Z' control frame (body[0] == 'Z') that arrived
// on the session at raddr: deliver it if it is for us, or forward it one hop
// to the destination's own direct session.
func handleE2EFrame(body []byte, raddr *net.UDPAddr) {
	s := GlobalSessions.GetByAddr(raddr)
	if s == nil || !s.Established() || !admissionOK(s.peerStatic, "e2e-in") {
		return
	}
	frame := body[1:]
	h, _, err := parseE2E(frame)
	if err != nil {
		statE2EDropAuth.Add(1)
		return
	}
	dstIP := net.IP(h.dst[:]).String()
	if isOverlayIPRevoked(dstIP) {
		statE2EDropPolicy.Add(1)
		return
	}
	me := e2eSelfIP()
	if me != "" && dstIP == me {
		e2eDeliverLocal(frame, raddr, s)
		return
	}

	// Transit. One hop only, and only to the session that OWNS the
	// destination — never onward to another relay, so no loops and no
	// relay-of-relay.
	if h.hop != 0 {
		statE2EDropRoute.Add(1)
		return
	}
	next := ipLearning.Lookup(dstIP)
	if next == nil || next.String() == raddr.String() {
		statE2EDropRoute.Add(1)
		return
	}
	ns := GlobalSessions.GetByAddr(next)
	if ns == nil || !ns.Established() || !admissionOK(ns.peerStatic, "e2e-out") ||
		!ipBindings.IsNodeAt(ns.peerStatic, dstIP) {
		statE2EDropRoute.Add(1)
		return
	}
	out := make([]byte, 0, len(ctlMagic)+len(body))
	out = append(append(out, ctlMagic...), body...)
	out[len(ctlMagic)+1+e2eOffHop] = 1
	_ = sendPacket(GlobalConn, next, ns, out)
	statE2EForwarded.Add(1)
}

func e2eDeliverLocal(frame []byte, raddr *net.UDPAddr, s *session) {
	now := time.Now()
	h, pt, err := e2eReceiver.open(gKP, gPSK, frame, s.peerStatic, e2ePQSecretLookup, now)
	srcIP := net.IP(h.src[:]).String()
	switch {
	case err == errE2ENoPQ:
		// The sender uses an ML-KEM secret we do not hold (we restarted, or
		// it expired). Unauthenticated, so the only response is a
		// rate-limited reset sealed to the key it claims — harmless if the
		// claim is false — and only toward an address that key owns.
		statE2EDropNoPQ.Add(1)
		if ipBindings.OwnedBy(h.sender, srcIP, false) && e2ePQState.shouldReset(h.sender, now) {
			if f, ok := e2eSealControl(h.sender, srcIP, resetPayload(h.pqid)); ok {
				e2eSendControl(srcIP, f)
			}
		}
		return
	case err == errE2EReplay:
		statE2EDropReplay.Add(1)
		return
	case err != nil:
		statE2EDropAuth.Add(1)
		return
	}
	sender := h.sender
	if revoked.isRevoked(sender) || revocations.isRevoked(sender) {
		statE2EDropPolicy.Add(1)
		return
	}
	if !admissionOK(sender, "e2e-sender") {
		statE2EDropPolicy.Add(1)
		return
	}
	if !inOverlaySubnet(srcIP) || !ipBindings.OwnedBy(sender, srcIP, true) {
		statE2EDropSource.Add(1)
		statRxDropIPBinding.Add(1)
		return
	}

	if !h.hasPQ() {
		// Classical envelope: key-exchange messages only, never data.
		if len(pt) == 0 {
			statE2EDropSource.Add(1)
			return
		}
		switch pt[0] {
		case e2eKindOffer:
			reply, err := e2ePQState.onOffer(sender, pt[1:], now)
			if err != nil {
				statE2EDropAuth.Add(1)
				return
			}
			// Route the reply back the way the offer came.
			ipLearning.Learn(srcIP, raddr)
			setPeerOverlayIP(sender, srcIP)
			if f, ok := e2eSealControl(sender, srcIP, reply); ok {
				e2eSendControl(srcIP, f)
			}
			// Whoever starts talking to us will usually expect answers:
			// start the exchange for our direction now rather than after the
			// first reply packet has to be held back.
			if _, back := e2ePQState.outbound(sender, now); back != nil {
				if f, ok := e2eSealControl(sender, srcIP, back); ok {
					e2eSendControl(srcIP, f)
				}
			}
		case e2eKindReply:
			if e2ePQState.onReply(sender, pt[1:], now) == nil {
				statE2EPQExchanges.Add(1)
				ipLearning.Learn(srcIP, raddr)
			} else {
				statE2EDropAuth.Add(1)
			}
		case e2eKindReset:
			if len(pt) == 5 {
				var id [4]byte
				copy(id[:], pt[1:])
				e2ePQState.onReset(sender, id)
			}
		default:
			// Includes IPv4: relayed data without an ML-KEM secret is refused.
			statE2EDropSource.Add(1)
		}
		return
	}

	me := e2eSelfIP()
	if !isIPv4Packet(pt) || extractIPv4Dst(pt) != me || extractIPv4Src(pt) != srcIP {
		statE2EDropSource.Add(1)
		return
	}
	// Route replies back the way this came. When the sealing node IS the
	// session peer (it flooded because it had no route yet) this is a direct
	// route; otherwise a relay route, which Learn never lets displace a live
	// direct one.
	ipLearning.Learn(srcIP, raddr)
	setPeerOverlayIP(sender, srcIP)
	statE2EOpened.Add(1)
	e2eDeliver(pt)
}

var e2eRosterPush struct {
	sync.Mutex
	last    time.Time
	pending bool
}

const e2eRosterPushGap = 3 * time.Second

// e2ePushRoster sends the roster to every admitted direct peer when a peer's
// address becomes known here. Relayed traffic can only be sealed once the
// sender knows the destination's key, and the roster is how a node learns the
// keys of peers it has no session with; waiting for the slow periodic gossip
// left newly joined nodes unreachable through a relay for up to a minute.
// Pushes are spaced e2eRosterPushGap apart, and one requested inside the gap
// is sent when it ends rather than dropped — otherwise two nodes joining
// together would leave the first without the second's key.
func e2ePushRoster() {
	e2eRosterPush.Lock()
	if e2eRosterPush.pending {
		e2eRosterPush.Unlock()
		return
	}
	if wait := e2eRosterPushGap - time.Since(e2eRosterPush.last); wait > 0 {
		e2eRosterPush.pending = true
		e2eRosterPush.Unlock()
		time.AfterFunc(wait, func() {
			e2eRosterPush.Lock()
			e2eRosterPush.pending = false
			e2eRosterPush.last = time.Now()
			e2eRosterPush.Unlock()
			e2eSendRosterToAll()
		})
		return
	}
	e2eRosterPush.last = time.Now()
	e2eRosterPush.Unlock()
	e2eSendRosterToAll()
}

func e2eSendRosterToAll() {
	if GlobalSessions == nil || GlobalConn == nil {
		return
	}
	frame := buildRosterFrame()
	if frame == nil {
		return
	}
	for _, a := range GlobalSessions.EstablishedAddrs() {
		if s := GlobalSessions.GetByAddr(a); s != nil && s.Established() && admissionOK(s.peerStatic, "roster") {
			_ = sendPacket(GlobalConn, a, s, frame)
		}
	}
}

// notePeerAddress records a peer's verified own address and, if it is new or
// changed, shares the roster so other peers can reach it through this node.
func notePeerAddress(pub [32]byte, ip string) {
	if peerOverlayIPByPub(pub) == ip {
		return
	}
	setPeerOverlayIP(pub, ip)
	if !e2eRosterPushOff.Load() {
		go e2ePushRoster()
	}
}

// e2eRosterPushOff disables the background push (unit tests swap the
// node-wide globals it reads).
var e2eRosterPushOff atomic.Bool

// refuseLegacyRelay handles the old plaintext 'R' relay frame: it is dropped,
// because honouring it would put payload in the clear on this node.
func refuseLegacyRelay(raddr *net.UDPAddr) {
	statE2EDropLegacy.Add(1)
	e2eLegacyLogMu.Lock()
	defer e2eLegacyLogMu.Unlock()
	if time.Since(e2eLegacyLogLast) < time.Minute {
		return
	}
	e2eLegacyLogLast = time.Now()
	log.Printf("[relay] refused a legacy plaintext relay frame from %s — that peer runs an older build; "+
		"relayed traffic now requires end-to-end encryption, so upgrade every node", raddr)
}

// sendOverlayViaSession sends an overlay-bound TUN packet over session s at
// addr: raw if s is the destination itself, otherwise sealed end-to-end so the
// relay only sees ciphertext. It reports whether anything was sent.
func sendOverlayViaSession(conn *net.UDPConn, addr *net.UDPAddr, s *session, pkt []byte, dst string) (bool, error) {
	if ipBindings.IsNodeAt(s.peerStatic, dst) {
		return true, sendPacket(conn, addr, s, pkt)
	}
	frame, ok := buildE2EFrame(pkt)
	if !ok {
		return false, nil
	}
	return true, sendPacket(conn, addr, s, frame)
}
