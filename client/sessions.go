package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
)

const sessionIdleTimeout = 5 * time.Minute
const sessionEvictInterval = 2 * time.Minute

// Retransmit / deadline knobs for the handshake state machines.
//
// These are tuned for BitTorrent-style hole-punching: both peers learn each
// other's endpoint from a tracker at roughly the same time, but possibly
// with several seconds of skew. Each side blasts msg1 at 300ms intervals to
//
//	(a) burn open the NAT pinhole on its own side, and
//	(b) maximize the chance the other side sees one of the retransmits
//	    after a few are dropped by NAT or transient internet loss.
//
// 8s deadline gives the simultaneous-init race a generous window to
// converge: even if peer A starts trying 3-4s before peer B does, B's first
// successful msg1 still falls inside A's window and the handshake completes.
const (
	handshakeMsg1RetransmitInterval = 300 * time.Millisecond
	handshakeTotalDeadline          = 8 * time.Second
	handshakeResponderMsg3Wait      = 8 * time.Second
)

// noiseEphemeralSize is the Noise XX ephemeral pubkey body length
// (X25519 public key, 32 bytes). Used for msg1 dedup and frame sizing.
const noiseEphemeralSize = 32

// Wire-level packet types. Every UDP packet on the overlay starts with one
// of these as its first byte so the receiver can route the packet to the
// right handler without guessing from length.
//
// Format on the wire:
//
//	[1 byte type] [variable body]
//
// Bodies:
//
//	PktMsg1:        32 bytes  (Noise XX ephemeral pubkey "e")
//	PktMsg2:        96 bytes  (Noise XX "e, ee, s, es")
//	PktMsg3:        64 bytes  (Noise XX "s, se")
//	PktData:        [8 bytes nonce][2 bytes len][len bytes ciphertext+MAC]
//	PktCookieReply: 32 bytes  (HMAC cookie, future DoS mitigation)
//
// The explicit 8-byte big-endian nonce on PktData is essential over UDP:
// Noise cipher states use an incrementing counter, and if sender and
// receiver counted packets independently, a single lost or reordered
// datagram would desync the counters and every subsequent Decrypt would
// fail. The sender transmits its counter; the receiver calls SetNonce with
// it before decrypting, with a 64-entry sliding window for replay defense.
const (
	PktMsg1        byte = 0x01
	PktMsg2        byte = 0x02
	PktMsg3        byte = 0x03
	PktData        byte = 0x04
	PktCookieReply byte = 0x05
)

// IsOverlayPacket returns true if the first byte of a UDP datagram
// identifies it as overlay traffic (as opposed to STUN or anything else
// sharing the socket).
func IsOverlayPacket(b byte) bool {
	return b == PktMsg1 || b == PktMsg2 || b == PktMsg3 || b == PktData || b == PktCookieReply
}

type backoffState struct {
	failures int
	until    time.Time
}

type session struct {
	addr        *net.UDPAddr
	send        *noise.CipherState
	recv        *noise.CipherState
	established bool
	lastSeen    time.Time

	// sendMu serializes access to the send cipher state and the send nonce
	// counter. Both the TUN->UDP path and the keepalive ticker encrypt with
	// the same CipherState; without this lock their SetNonce/Encrypt pairs
	// interleave and produce garbage on the wire.
	sendMu    sync.Mutex
	sendNonce uint64

	// Anti-replay sliding window for inbound data packets. Only touched by
	// the single UDP read goroutine, so no lock is needed.
	recvHighest uint64
	recvBitmap  uint64
	recvAny     bool

	// msg3Frame is the final handshake frame we sent as initiator. If the
	// responder never received it (UDP loss) it keeps retransmitting msg2;
	// we answer those retransmits by resending msg3 so the responder can
	// complete. Nil on responder-side sessions.
	msg3Frame []byte
}

// replayCheck returns true if a data packet with this nonce should be
// accepted (not yet seen, not too old). Call replayMark after the packet
// authenticates successfully.
func (s *session) replayCheck(nonce uint64) bool {
	if !s.recvAny {
		return true
	}
	if nonce > s.recvHighest {
		return true
	}
	diff := s.recvHighest - nonce
	if diff >= 64 {
		return false // too old — outside the window
	}
	return s.recvBitmap&(1<<diff) == 0
}

// replayMark records a successfully authenticated nonce in the window.
func (s *session) replayMark(nonce uint64) {
	if !s.recvAny {
		s.recvAny = true
		s.recvHighest = nonce
		s.recvBitmap = 1
		return
	}
	if nonce > s.recvHighest {
		shift := nonce - s.recvHighest
		if shift >= 64 {
			s.recvBitmap = 1
		} else {
			s.recvBitmap = (s.recvBitmap << shift) | 1
		}
		s.recvHighest = nonce
		return
	}
	diff := s.recvHighest - nonce
	if diff < 64 {
		s.recvBitmap |= 1 << diff
	}
}

// pendingHandshake represents an in-progress handshake for a specific peer.
//
// firstMsg1 holds the first msg1 body the responder ever accepted from this
// peer; subsequent msg1s with the same body are filtered as retransmits.
//
// ourEphemeralPub holds the 32-byte ephemeral pubkey we sent in our outbound
// msg1 (initiator side only). It is the tiebreaker for the simultaneous-init
// race: when both peers initiate at the same time, the side whose ephemeral
// pubkey sorts lower wins and stays initiator; the other side aborts and
// becomes responder. Both peers can compute the same answer independently
// since the ephemeral pubkeys are exchanged in plaintext as the msg1 body.
//
// isResponder records which role we are; without it, Deliver can't recover
// the role we committed to on first contact and would misroute retransmits.
//
// responderSpawned is set under the table lock the first (and only) time
// Deliver launches a handleResponder goroutine for this pending. It
// prevents duplicate spawns on msg1 retransmits.
//
// abortInitiator, if non-nil, will be closed exactly once when we decide to
// stop being the initiator (typically because we lost a simultaneous-init
// race). The initiator goroutine selects on this channel and tears down.
type pendingHandshake struct {
	peer             *net.UDPAddr
	msgs             chan []byte
	firstMsg1        []byte
	ourEphemeralPub  []byte
	isResponder      bool
	responderSpawned bool
	abortInitiator   chan struct{}
}

type SessionTable struct {
	mu            sync.RWMutex
	byAddr        map[string]*session
	pendingByAddr map[string]*pendingHandshake
	peerBackoff   map[string]*backoffState
	stopCh        chan struct{}
	udpConn       *net.UDPConn
	onSessionLost func(*net.UDPAddr)
}

func NewSessionTable(conn *net.UDPConn) *SessionTable {
	t := &SessionTable{
		byAddr:        map[string]*session{},
		pendingByAddr: map[string]*pendingHandshake{},
		peerBackoff:   map[string]*backoffState{},
		stopCh:        make(chan struct{}),
		udpConn:       conn,
	}
	go t.evictLoop()
	return t
}

func (t *SessionTable) evictLoop() {
	ticker := time.NewTicker(sessionEvictInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.evictStale()
		case <-t.stopCh:
			return
		}
	}
}

func (t *SessionTable) evictStale() {
	t.mu.Lock()
	now := time.Now()
	var lost []*net.UDPAddr
	for addr, s := range t.byAddr {
		if now.Sub(s.lastSeen) > sessionIdleTimeout {
			delete(t.byAddr, addr)
			if s.established && s.addr != nil {
				lost = append(lost, s.addr)
			}
		}
	}
	cb := t.onSessionLost
	t.mu.Unlock()

	if cb != nil {
		for _, addr := range lost {
			go cb(addr)
		}
	}
}

func (t *SessionTable) Close() {
	select {
	case <-t.stopCh:
	default:
		close(t.stopCh)
	}
}

func (t *SessionTable) SetSessionLostCallback(fn func(*net.UDPAddr)) {
	t.mu.Lock()
	t.onSessionLost = fn
	t.mu.Unlock()
}

func (t *SessionTable) GetByAddr(addr *net.UDPAddr) *session {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byAddr[addr.String()]
}

func (t *SessionTable) Evict(addr *net.UDPAddr) {
	t.mu.Lock()
	delete(t.byAddr, addr.String())
	t.mu.Unlock()
}

// RecordFailure / RecordSuccess / ShouldSkip implement a soft back-off.
// The ceiling is deliberately low (60s, not 10min) because the hole-punch
// convergence pattern requires regular retries during the first few
// minutes after a peer is discovered. Long back-offs kill convergence.
func (t *SessionTable) RecordFailure(addr *net.UDPAddr) {
	key := addr.String()
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.peerBackoff[key]
	if b == nil {
		b = &backoffState{}
		t.peerBackoff[key] = b
	}
	b.failures++
	// 5s, 10s, 20s, 40s, 60s (cap). Each step doubles to keep noise low
	// once a peer is clearly unreachable, but never grows past one minute
	// — many internet peers come and go on tracker swarms, and we want to
	// pick them up quickly when they reappear.
	steps := []time.Duration{5, 10, 20, 40, 60}
	idx := b.failures - 1
	if idx >= len(steps) {
		idx = len(steps) - 1
	}
	b.until = time.Now().Add(steps[idx] * time.Second)
}

func (t *SessionTable) RecordSuccess(addr *net.UDPAddr) {
	t.mu.Lock()
	delete(t.peerBackoff, addr.String())
	t.mu.Unlock()
}

func (t *SessionTable) ShouldSkip(addr *net.UDPAddr) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if b := t.peerBackoff[addr.String()]; b != nil {
		return time.Now().Before(b.until)
	}
	return false
}

func (t *SessionTable) set(addr *net.UDPAddr, s *session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s.lastSeen = time.Now()
	t.byAddr[addr.String()] = s
}

func (t *SessionTable) EstablishedAddrs() []*net.UDPAddr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := []*net.UDPAddr{}
	for _, s := range t.byAddr {
		if s.established {
			out = append(out, s.addr)
		}
	}
	return out
}

func (s *session) Established() bool {
	return s != nil && s.established && s.send != nil && s.recv != nil
}

// TouchLastSeen bumps lastSeen on the session for addr to now. Called when
// we successfully decrypt a data packet from the peer, so a busy session
// does not get evicted as idle.
func (t *SessionTable) TouchLastSeen(addr *net.UDPAddr) {
	t.mu.Lock()
	if s := t.byAddr[addr.String()]; s != nil {
		s.lastSeen = time.Now()
	}
	t.mu.Unlock()
}

func derivePrologue(psk []byte) []byte {
	if len(psk) == 0 {
		return nil
	}
	h := sha256.Sum256(append([]byte("OVLY-PSK-1:"), psk...))
	return h[:]
}

func peerIDFromSession(kp keypair) string {
	b := make([]byte, 12)
	for i := 0; i < 12; i++ {
		b[i] = kp.pub[i]
	}
	return hex.EncodeToString(b)[:12]
}

// getOrCreateInitiatorPending atomically gets the existing session or
// creates a new initiator-side pending handshake. Return tuple:
//   - existing established session (or nil)
//   - the pending we'll use (newly created or already existing)
//   - true if WE created it (we should run the initiator goroutine)
//   - true if someone ELSE already had a pending here (we lost the race)
func (t *SessionTable) getOrCreateInitiatorPending(addr *net.UDPAddr) (*session, *pendingHandshake, bool, bool) {
	key := addr.String()

	t.mu.RLock()
	if s := t.byAddr[key]; s != nil && s.Established() {
		t.mu.RUnlock()
		return s, nil, false, false
	}
	t.mu.RUnlock()

	t.mu.Lock()
	defer t.mu.Unlock()

	if s := t.byAddr[key]; s != nil && s.Established() {
		return s, nil, false, false
	}

	if p, ok := t.pendingByAddr[key]; ok {
		return nil, p, false, true
	}

	p := &pendingHandshake{
		peer:           addr,
		msgs:           make(chan []byte, 8),
		isResponder:    false,
		abortInitiator: make(chan struct{}),
	}
	t.pendingByAddr[key] = p
	return nil, p, true, false
}

var ErrHandshakeInProgress = errors.New("handshake already in progress for this peer")
var ErrHandshakeAborted = errors.New("handshake aborted by simultaneous-init tiebreak")

// EnsureSession is the initiator side of a Noise XX handshake.
//
// Wire framing: every UDP packet has a 1-byte type prefix in the 0x01-0x05
// range. msg1/2/3 carry the raw Noise body after the type byte; data frames
// carry a 2-byte length prefix then the ciphertext.
//
// msg1 is retransmitted every handshakeMsg1RetransmitInterval until either
// msg2 arrives or the total deadline expires. This serves two purposes:
//
//  1. UDP packet loss tolerance. Single-shot UDP across the public internet
//     has measurable loss rates.
//
//  2. NAT hole punching. When two peers behind NAT both initiate
//     simultaneously, each side's outbound msg1 trains its local NAT to
//     accept inbound traffic from the peer. The simultaneous-init case is
//     resolved by an ephemeral-pubkey tiebreak in Deliver — the side whose
//     ephemeral sorts lower stays initiator; the other aborts and becomes
//     responder. Both reach the same answer without coordination.
func (t *SessionTable) EnsureSession(addr *net.UDPAddr, kp keypair, psk []byte) (*session, error) {
	if s := t.GetByAddr(addr); s != nil && s.Established() {
		return s, nil
	}

	existing, p, _, lost := t.getOrCreateInitiatorPending(addr)
	if existing != nil {
		return existing, nil
	}

	if lost {
		return nil, ErrHandshakeInProgress
	}

	key := addr.String()
	pending := p.msgs

	cleanupPending := func() {
		t.mu.Lock()
		// Only delete if it's still OUR pending (might have been replaced
		// by a responder pending after a simultaneous-init tiebreak loss).
		if cur, ok := t.pendingByAddr[key]; ok && cur == p {
			delete(t.pendingByAddr, key)
		}
		t.mu.Unlock()
	}

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		StaticKeypair: noise.DHKey{Private: kp.priv[:], Public: kp.pub[:]},
		Prologue:      derivePrologue(psk),
	})
	if err != nil {
		cleanupPending()
		return nil, err
	}

	// msg1: write E (32 bytes Noise body, sent as [PktMsg1][32 bytes]).
	msgE, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		cleanupPending()
		return nil, err
	}

	// Record our ephemeral pubkey so Deliver can run the simultaneous-
	// init tiebreak if the peer sends us their msg1 while we're still
	// here. Must happen under lock so Deliver sees a consistent view.
	t.mu.Lock()
	p.ourEphemeralPub = append([]byte(nil), msgE...)
	t.mu.Unlock()

	msg1Frame := append([]byte{PktMsg1}, msgE...)

	if _, err := t.udpConn.WriteToUDP(msg1Frame, addr); err != nil {
		cleanupPending()
		return nil, err
	}

	deadline := time.Now().Add(handshakeTotalDeadline)
	retransmit := time.NewTicker(handshakeMsg1RetransmitInterval)
	defer retransmit.Stop()

	var payload []byte
waitForR:
	for {
		if !time.Now().Before(deadline) {
			cleanupPending()
			return nil, errors.New("handshake timeout reading R")
		}
		select {
		case payload = <-pending:
			// Initiator's pending.msgs only receives msg2 bodies (Deliver
			// filters by type and role). Break out to process it.
			break waitForR
		case <-p.abortInitiator:
			// We lost the simultaneous-init tiebreak. Deliver has already
			// replaced our pending with a responder pending and spawned
			// handleResponder. Just exit quietly — the responder path
			// will finish the handshake.
			return nil, ErrHandshakeAborted
		case <-retransmit.C:
			// Refresh the NAT pinhole; the peer may not have started its
			// outbound flow yet. Ignore send errors — best effort.
			_, _ = t.udpConn.WriteToUDP(msg1Frame, addr)
		}
	}

	if _, _, _, err = hs.ReadMessage(nil, payload); err != nil {
		cleanupPending()
		return nil, err
	}

	// msg3: Write S — final message; produces cipher states cs1, cs2.
	msgS, cs1, cs2, err := hs.WriteMessage(nil, nil)
	if err != nil {
		cleanupPending()
		return nil, err
	}
	msg3Frame := append([]byte{PktMsg3}, msgS...)

	cleanupPending()

	if _, err := t.udpConn.WriteToUDP(msg3Frame, addr); err != nil {
		return nil, err
	}

	// Initiator: send with cs1 (initiator→responder), recv with cs2.
	t.set(addr, &session{
		addr:        addr,
		send:        cs1,
		recv:        cs2,
		established: true,
		lastSeen:    time.Now(),
		msg3Frame:   msg3Frame,
	})
	return t.GetByAddr(addr), nil
}

// Deliver routes an inbound packet to the right handshake or session. typ
// is the first byte of the UDP datagram; body is everything after it.
// Returns true if the handshake layer consumed the packet; false means the
// caller should treat it as a data frame and decrypt against the
// established session.
func (t *SessionTable) Deliver(raddr *net.UDPAddr, typ byte, body []byte, kp keypair, psk []byte) bool {
	key := raddr.String()

	if typ == PktData {
		return false
	}
	if typ == PktCookieReply {
		return true
	}
	if typ != PktMsg1 && typ != PktMsg2 && typ != PktMsg3 {
		return true
	}

	t.mu.Lock()
	s := t.byAddr[key]

	// Peer restarted: a fresh msg1 from an established peer drops our
	// stale session and starts over as the responder.
	if s != nil && s.Established() && typ == PktMsg1 {
		delete(t.byAddr, key)
		s = nil
	}

	// Established session + non-msg1 handshake byte. A msg2 here means the
	// responder never saw our msg3 (lost in flight) and is retransmitting;
	// resend msg3 so it can complete its side. Anything else is a stale
	// fragment — drop.
	if s != nil && s.Established() && typ != PktMsg1 {
		var resend []byte
		if typ == PktMsg2 && s.msg3Frame != nil {
			resend = s.msg3Frame
		}
		t.mu.Unlock()
		if resend != nil {
			_, _ = t.udpConn.WriteToUDP(resend, raddr)
		}
		return true
	}

	p, ok := t.pendingByAddr[key]
	var isResponder bool
	var spawnResponder bool
	if !ok {
		// No pending entry. Only msg1 may start one.
		if typ != PktMsg1 {
			t.mu.Unlock()
			return true
		}
		p = &pendingHandshake{
			peer:             raddr,
			msgs:             make(chan []byte, 8),
			isResponder:      true,
			responderSpawned: true,
		}
		t.pendingByAddr[key] = p
		isResponder = true
		spawnResponder = true
	} else {
		isResponder = p.isResponder
	}

	// ---- Simultaneous-init handling ----
	//
	// Tricky case: we are already running as initiator for this peer, and
	// now their msg1 arrives. The classic strict-protocol answer is "drop
	// it" — but that's exactly what causes the BitTorrent-style failure
	// mode where both peers initiate at the same time from the tracker
	// and each drops the other's msg1.
	//
	// Resolution: compare ephemeral pubkeys lexicographically. The side
	// whose ephemeral is smaller is the canonical initiator; the other
	// side aborts initiator state and becomes responder. Both peers
	// compute the same answer using only data already on the wire (the
	// msg1 bodies are the ephemeral pubkeys), so the resolution is
	// race-free.
	if !isResponder && typ == PktMsg1 {
		if p.ourEphemeralPub == nil {
			// We haven't written our own msg1 yet — race with
			// EnsureSession. Drop theirs; retransmits will arrive.
			t.mu.Unlock()
			return true
		}
		if bytes.Compare(p.ourEphemeralPub, body) < 0 {
			// We win the tiebreak. Stay initiator; drop their msg1.
			// Their msg1 retransmits will keep arriving; we keep
			// dropping them. They lose the same comparison on their
			// side and abort to responder.
			t.mu.Unlock()
			return true
		}
		// We lose. Abort initiator and become responder.
		oldP := p
		p = &pendingHandshake{
			peer:             raddr,
			msgs:             make(chan []byte, 8),
			isResponder:      true,
			responderSpawned: true,
			firstMsg1:        append([]byte(nil), body...),
		}
		t.pendingByAddr[key] = p
		// Pre-load msg1 onto the new pending's channel so
		// handleResponder reads it without waiting for a retransmit.
		p.msgs <- append([]byte(nil), body...)
		// Tell the initiator goroutine to exit cleanly.
		if oldP.abortInitiator != nil {
			select {
			case <-oldP.abortInitiator:
			default:
				close(oldP.abortInitiator)
			}
		}
		t.mu.Unlock()
		go handleResponder(t.udpConn, raddr, p, kp, psk)
		return true
	}

	// Role-aware type gating for non-tiebreak cases.
	if !isResponder {
		// Initiator: only msg2 means anything.
		if typ != PktMsg2 {
			t.mu.Unlock()
			return true
		}
	} else {
		// Responder: msg1 (handled below for dedup) and msg3 are valid.
		if typ == PktMsg2 {
			t.mu.Unlock()
			return true
		}
	}

	// Responder dedups msg1 retransmits so they don't get re-fed to Noise.
	if typ == PktMsg1 {
		if p.firstMsg1 != nil && bytes.Equal(p.firstMsg1, body) {
			t.mu.Unlock()
			return true
		}
		if p.firstMsg1 == nil {
			p.firstMsg1 = append([]byte(nil), body...)
		}
	}
	t.mu.Unlock()

	// Push body onto pending.msgs. If the channel is full, drop —
	// retransmits will cover for us.
	select {
	case p.msgs <- body:
	default:
	}

	if spawnResponder {
		go handleResponder(t.udpConn, raddr, p, kp, psk)
	}
	return true
}

// handleResponder runs the responder side of the Noise XX handshake.
//
// Noise XX message flow — responder side:
//
//	msg1: initiator  ReadMessage   <-  e
//	msg2: responder  WriteMessage  ->  e, ee, s, es        (we may retransmit)
//	msg3: initiator  ReadMessage   <-  s, se               (produces cs1, cs2)
//
// Cipher state assignment for the responder:
//
//	cs1 = initiator→responder direction → responder RECV
//	cs2 = responder→initiator direction → responder SEND
func handleResponder(conn *net.UDPConn, addr *net.UDPAddr, pending *pendingHandshake, kp keypair, psk []byte) {
	key := addr.String()
	cleanupPending := func() {
		GlobalSessions.mu.Lock()
		if cur, ok := GlobalSessions.pendingByAddr[key]; ok && cur == pending {
			delete(GlobalSessions.pendingByAddr, key)
		}
		GlobalSessions.mu.Unlock()
	}
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeXX,
		Initiator:     false,
		StaticKeypair: noise.DHKey{Private: kp.priv[:], Public: kp.pub[:]},
		Prologue:      derivePrologue(psk),
	})
	if err != nil {
		cleanupPending()
		return
	}

	// msg1: read E. Already enqueued by Deliver as the triggering packet.
	var payload []byte
	select {
	case payload = <-pending.msgs:
	case <-time.After(handshakeResponderMsg3Wait):
		cleanupPending()
		return
	}

	if _, _, _, err = hs.ReadMessage(nil, payload); err != nil {
		cleanupPending()
		return
	}

	msgR, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		cleanupPending()
		return
	}
	msg2Frame := append([]byte{PktMsg2}, msgR...)

	if _, err := conn.WriteToUDP(msg2Frame, addr); err != nil {
		cleanupPending()
		return
	}

	deadline := time.Now().Add(handshakeResponderMsg3Wait)
	retransmit := time.NewTicker(handshakeMsg1RetransmitInterval)
	defer retransmit.Stop()

	var payload3 []byte
waitForS:
	for {
		if !time.Now().Before(deadline) {
			cleanupPending()
			return
		}
		select {
		case payload3 = <-pending.msgs:
			// Deliver enqueues only msg1 (deduped) and msg3 bodies for
			// the responder. Bodies of length 32 are msg1 retransmits
			// that slipped through dedup; ignore.
			if len(payload3) == noiseEphemeralSize {
				continue
			}
			break waitForS
		case <-retransmit.C:
			_, _ = conn.WriteToUDP(msg2Frame, addr)
		}
	}

	_, cs1, cs2, err := hs.ReadMessage(nil, payload3)
	if err != nil {
		cleanupPending()
		return
	}

	// Responder: send with cs2, recv with cs1.
	GlobalSessions.set(addr, &session{
		addr:        addr,
		send:        cs2,
		recv:        cs1,
		established: true,
		lastSeen:    time.Now(),
	})
	log.Printf("session established with %s (responder)", addr)

	cleanupPending()
}
