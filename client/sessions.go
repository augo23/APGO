package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
)

const sessionIdleTimeout = 5 * time.Minute
const sessionEvictInterval = 15 * time.Second

// gKeepaliveInterval / sessionStaleTimeout are set from keepalive_seconds at
// startup (defaults: 10s / 45s). Both sides keepalive every interval, so an
// ESTABLISHED session with no inbound for sessionStaleTimeout has a dead or
// one-way path (blocked inbound, expired NAT mapping, rebooted peer, …).
// Tearing it down promptly — instead of waiting out sessionIdleTimeout —
// lets the recovery machinery (announce, PEX, coordinated punch, relay)
// rebuild a working path within seconds on ANY kind of network, rather than
// blackholing traffic for up to 5 minutes.
var (
	gKeepaliveInterval  = 10 * time.Second
	sessionStaleTimeout = 45 * time.Second
)

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

	// decryptFails counts consecutive failed decrypts since the last
	// successful one (see NoteDecryptFailure). Guarded by the table lock.
	decryptFails int

	// msg3Frame is the final handshake frame we sent as initiator. If the
	// responder never received it (UDP loss) it keeps retransmitting msg2;
	// we answer those retransmits by resending msg3 so the responder can
	// complete. Nil on responder-side sessions.
	msg3Frame []byte

	// peerStatic is the remote peer's Noise static public key, learned during
	// the handshake. It is the stable cryptographic identity of the peer
	// (their overlay IP derives from it) and the key the admin revocation list
	// is keyed on. createdAt/initiator are metadata surfaced to the dashboard.
	peerStatic [32]byte
	createdAt  time.Time
	initiator  bool
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
	var lostKeys [][32]byte
	for addr, s := range t.byAddr {
		// Established sessions go stale FAST (no inbound for ~3 keepalive
		// intervals = dead/one-way path); half-open handshake state keeps the
		// long idle timeout (it has its own retransmit deadlines).
		limit := sessionIdleTimeout
		if s.established {
			limit = sessionStaleTimeout
		}
		if now.Sub(s.lastSeen) > limit {
			delete(t.byAddr, addr)
			if s.established && s.addr != nil {
				lost = append(lost, s.addr)
				lostKeys = append(lostKeys, s.peerStatic)
				log.Printf("[liveness] session %s silent for %v — tearing down to force re-punch/relay",
					addr, now.Sub(s.lastSeen).Round(time.Second))
			}
		}
	}
	cb := t.onSessionLost
	t.mu.Unlock()

	for i, addr := range lost {
		// Drop the overlay-IP mapping too, so traffic for that peer falls back
		// to the relay/discovery path immediately instead of blackholing into
		// the dead endpoint.
		ipLearning.ForgetAddr(addr)
		t.dropPeerCryptoIfNoRoute(lostKeys[i])
		if cb != nil {
			go cb(addr)
		}
	}
}

// dropPeerCryptoIfNoRoute clears the per-peer PQ state (and cached PQ-status
// flag) once the LAST established route to that peer identity is gone. With
// multi-route peers a single torn-down address may leave a live backup route,
// in which case the negotiated ML-KEM layer must be KEPT; only when nothing
// remains do we forget it so the next reconnect renegotiates cleanly.
func (t *SessionTable) dropPeerCryptoIfNoRoute(key [32]byte) {
	if key == ([32]byte{}) {
		return
	}
	t.mu.RLock()
	for _, s := range t.byAddr {
		if s.established && s.peerStatic == key {
			t.mu.RUnlock()
			return // a route still exists — keep the PQ layer
		}
	}
	t.mu.RUnlock()
	pqForget(key)
	forgetPeerPQStatus(key)
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
	var key [32]byte
	if s := t.byAddr[addr.String()]; s != nil {
		key = s.peerStatic
	}
	delete(t.byAddr, addr.String())
	t.mu.Unlock()
	// Clear negotiated PQ state if this was the peer's last route (wake/resume
	// evicts every session — the reconnect must renegotiate the ML-KEM layer,
	// not reuse a key the peer may have discarded when it slept).
	t.dropPeerCryptoIfNoRoute(key)
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
	s.lastSeen = time.Now()
	key := addr.String()
	t.byAddr[key] = s

	// MULTI-ROUTE PEERS. Discovery is multi-path (tracker, PEX, LAN beacon),
	// so the same peer can legitimately hold sessions at SEVERAL addresses —
	// its LAN address and its public/WAN address. These are ROUTES to one
	// device, and both are KEPT: the extra route is a warm standby (its
	// keepalives hold the NAT pinhole open), so when the primary path dies —
	// a phone walking out of Wi-Fi range, a laptop switching networks — the
	// stale-timeout eviction ForgetAddr's the primary and the backup's next
	// keepalive takes over routing within seconds. Nothing is deleted here,
	// so the two ends can never disagree about which keys are live (deleting
	// is what caused the "cipher: message authentication failed" desync
	// storms). The UI collapses same-key routes and shows only the primary
	// (see Snapshot).
	//
	// ROUTING PREFERENCE: LAN beats WAN. If this NEW session is a LAN path
	// (or the peer has no LAN path), it becomes the primary route: existing
	// mappings at the older addresses are repointed to it. If the new
	// session is a WAN path while a LAN session exists, routing stays on the
	// LAN session and the new one just sits as the backup (sticky Learn in
	// ip_learning.go keeps its keepalives from stealing the route).
	//
	// LOCK ORDER: collect addresses under t.mu, but touch ipLearning only
	// AFTER releasing it. ipLearning.Learn takes its own lock and then reads
	// this table — calling RemapAddr while holding t.mu is the classic AB-BA
	// deadlock, which froze the receive loop and hung the control API.
	var others []*net.UDPAddr
	takeover := true
	var zeroKey [32]byte
	if s.peerStatic != zeroKey {
		newPrivate := isPrivateUDPAddr(addr)
		for k, old := range t.byAddr {
			if k == key || !old.established || old.peerStatic != s.peerStatic {
				continue
			}
			if old.addr != nil {
				others = append(others, old.addr)
			}
			if isPrivateUDPAddr(old.addr) && !newPrivate {
				takeover = false // existing LAN route stays primary
			}
		}
	}
	t.mu.Unlock()
	if len(others) == 0 {
		return
	}
	if !takeover {
		log.Printf("[session] LAN route stays primary for this peer; new %s kept as backup route (roaming failover)", key)
		return
	}
	for _, oldAddr := range others {
		ipLearning.RemapAddr(oldAddr, addr)
	}
	log.Printf("[session] %s is now the primary route for this peer (%d backup route(s) kept for roaming failover)", key, len(others))
}

// isPrivateUDPAddr reports whether a terminates at an RFC1918/link-local/
// loopback address — i.e. a directly-routable LAN path rather than a
// router-hairpin or internet path.
func isPrivateUDPAddr(a *net.UDPAddr) bool {
	if a == nil || a.IP == nil {
		return false
	}
	return a.IP.IsPrivate() || a.IP.IsLinkLocalUnicast() || a.IP.IsLoopback()
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
		s.decryptFails = 0
	}
	t.mu.Unlock()
}

// NoteDecryptFailure records a failed decrypt on the established session for
// addr. A failed decrypt is normally garbage or spoofing and must NOT tear the
// session down (that would let third parties kill tunnels). But a session
// where EVERYTHING fails and NOTHING has decrypted for multiple keepalive
// intervals is not being spoofed — it's key desync: the peer re-keyed onto a
// different session (e.g. an older build holding duplicate sessions to us).
// Waiting out the full stale timer blackholes traffic for up to a minute;
// tear down early so both sides re-handshake and converge. A live peer's
// keepalives decrypt fine and reset the counter every interval, so a spoof
// flood can never trip this (lastSeen stays fresh).
func (t *SessionTable) NoteDecryptFailure(addr *net.UDPAddr) {
	key := addr.String()
	t.mu.Lock()
	s := t.byAddr[key]
	if s == nil || !s.established {
		t.mu.Unlock()
		return
	}
	s.decryptFails++
	quiet := time.Since(s.lastSeen)
	if s.decryptFails < 10 || quiet < 2*gKeepaliveInterval+2*time.Second {
		t.mu.Unlock()
		return
	}
	fails := s.decryptFails
	peerKey := s.peerStatic
	cb := t.onSessionLost
	delete(t.byAddr, key)
	t.mu.Unlock()
	log.Printf("[liveness] session %s: %d consecutive decrypt failures, no valid traffic for %v — key desync, tearing down to re-handshake",
		key, fails, quiet.Round(time.Second))
	ipLearning.ForgetAddr(addr)
	// Key desync often means the peer restarted and lost its ML-KEM state;
	// clear ours (if no route remains) so the reconnect re-offers PQ instead
	// of both sides assuming a dead layer is still up.
	t.dropPeerCryptoIfNoRoute(peerKey)
	if cb != nil {
		go cb(addr)
	}
}

// logDecryptError logs a failed decrypt, damped to a few lines per peer per
// 30-second window. During a mixed-build transition an old-build peer holding
// a superseded duplicate session produces one failed keepalive every interval
// — harmless (traffic rides the live session), but at packet rate it floods
// the log and looks like a catastrophe. Failures still COUNT toward the
// key-desync teardown (NoteDecryptFailure); only the logging is damped.
type decryptErrState struct {
	windowStart time.Time
	logged      int
	suppressed  int
}

var (
	decryptErrMu sync.Mutex
	decryptErrs  = map[string]*decryptErrState{}
)

func logDecryptError(addr string, err error) {
	decryptErrMu.Lock()
	st := decryptErrs[addr]
	if st == nil {
		st = &decryptErrState{}
		decryptErrs[addr] = st
	}
	now := time.Now()
	if now.Sub(st.windowStart) > 30*time.Second {
		suppressed := st.suppressed
		st.windowStart = now
		st.logged = 1
		st.suppressed = 0
		decryptErrMu.Unlock()
		if suppressed > 0 {
			log.Printf("decrypt/decode error from %s: %v (+%d similar suppressed over the last 30s — likely a peer on an old build still sending on a superseded session)", addr, err, suppressed)
		} else {
			log.Printf("decrypt/decode error from %s: %v", addr, err)
		}
		return
	}
	if st.logged < 3 {
		st.logged++
		decryptErrMu.Unlock()
		log.Printf("decrypt/decode error from %s: %v", addr, err)
		return
	}
	st.suppressed++
	decryptErrMu.Unlock()
}

func derivePrologue(psk []byte) []byte {
	if len(psk) == 0 {
		return nil
	}
	h := sha256.Sum256(append([]byte("OVLY-PSK-1:"), psk...))
	return h[:]
}

// pskAuthKey derives the 32-byte pre-shared key that is mixed into the Noise
// KEY SCHEDULE (Noise XXpsk0). Unlike the prologue (which only binds the
// transcript hash), this makes the session key depend on the symmetric PSK, so
// authentication and confidentiality survive a quantum computer that breaks the
// X25519 DH: without the PSK an attacker cannot derive the key or impersonate a
// member, even with quantum. Distinct label from the prologue.
func pskAuthKey(psk []byte) []byte {
	h := sha256.Sum256(append([]byte("OVLY-PSK-AUTH-1:"), psk...))
	return h[:]
}

// pqAuth enables quantum-resistant handshake authentication by mixing the PSK
// into the Noise key schedule (XXpsk0). OFF by default: it changes the handshake
// wire format, so EVERY node must have the same setting, and a node with it off
// is compatible with the classic (prologue-only) handshake. Turn it on network-
// wide (pq_auth: true / PQ_AUTH=1) only once the whole fleet runs a build that
// has it. Set from config in main().
var pqAuth bool

// noiseHandshakeConfig builds the handshake config. With pqAuth on and a PSK set,
// the PSK is placed at position 0 (XXpsk0) so it authenticates the whole
// handshake in a quantum-resistant way. Otherwise the PSK only binds the
// transcript via the prologue (the classic, widely-compatible handshake).
func noiseHandshakeConfig(cs noise.CipherSuite, initiator bool, kp keypair, psk []byte) noise.Config {
	cfg := noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeXX,
		Initiator:     initiator,
		StaticKeypair: noise.DHKey{Private: kp.priv[:], Public: kp.pub[:]},
		Prologue:      derivePrologue(psk),
	}
	if pqAuth && len(psk) > 0 {
		cfg.PresharedKey = pskAuthKey(psk)
		cfg.PresharedKeyPlacement = 0 // XXpsk0
	}
	return cfg
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

	cs := noise.NewCipherSuite(noise.DH25519, noiseCipher, noise.HashBLAKE2b)
	hs, err := noise.NewHandshakeState(noiseHandshakeConfig(cs, true, kp, psk))
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
			return nil, errors.New("no handshake reply (peer unreachable: NAT/firewall blocking the direct path, or peer offline — the mesh will relay if a path exists)")
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
		// We got a reply but couldn't authenticate it: the two sides derived
		// different handshake keys. This is a CONFIG/BUILD mismatch, not NAT —
		// every node must run the SAME build and share the same psk + cipher.
		// It's the classic symptom of a partial upgrade (some nodes rebuilt, some
		// not) or a psk/cipher that differs between nodes.
		return nil, fmt.Errorf("handshake crypto mismatch (check every node runs the same build and the same psk + cipher): %w", err)
	}

	// Capture the responder's static public key (learned from msg2) and refuse
	// to finish the handshake with a peer an operator has revoked via the admin
	// dashboard.
	var peerStatic [32]byte
	copy(peerStatic[:], hs.PeerStatic())
	if revoked.isRevoked(peerStatic) || revocations.isRevoked(peerStatic) {
		cleanupPending()
		return nil, errors.New("peer is revoked")
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
		peerStatic:  peerStatic,
		createdAt:   time.Now(),
		initiator:   true,
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

	// Peer restarted: a fresh msg1 from an established peer starts a new
	// responder handshake. Crucially, the EXISTING session is KEPT until the
	// new handshake authenticates (handleResponder replaces it atomically
	// via set() once msg3 verifies). The old behavior deleted the session
	// here — before the sender had proven anything — so any stray msg1 (a
	// peer's redundant hole-punch toward our tracker-advertised endpoint,
	// retransmits from a simultaneous-init race, or a spoofed source
	// address) instantly blackholed a WORKING tunnel until a re-handshake
	// completed, which showed up as periodic multi-second connection drops.
	// Pending handshakes live in their own map, so the responder handshake
	// below proceeds fine alongside the live session.

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
		if p.firstMsg1 != nil {
			// A DIFFERENT msg1 while a responder handshake is mid-flight: the
			// initiator gave up on its previous attempt and restarted with a
			// fresh ephemeral. Feeding the new msg1 into the OLD handshake (or
			// answering it with the old msg2) makes the initiator fail with a
			// misleading "handshake crypto mismatch" and back off for up to
			// 60s — the "phone takes forever to find the mac" symptom.
			// Replace the stale pending with a fresh responder handshake; the
			// old goroutine notices it was superseded and exits.
			np := &pendingHandshake{
				peer:             raddr,
				msgs:             make(chan []byte, 8),
				isResponder:      true,
				responderSpawned: true,
				firstMsg1:        append([]byte(nil), body...),
			}
			t.pendingByAddr[key] = np
			np.msgs <- append([]byte(nil), body...)
			t.mu.Unlock()
			go handleResponder(t.udpConn, raddr, np, kp, psk)
			return true
		}
		p.firstMsg1 = append([]byte(nil), body...)
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
	cs := noise.NewCipherSuite(noise.DH25519, noiseCipher, noise.HashBLAKE2b)
	hs, err := noise.NewHandshakeState(noiseHandshakeConfig(cs, false, kp, psk))
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
			// Superseded by a fresh responder handshake (the initiator
			// restarted)? Then STOP retransmitting our stale msg2 — the
			// initiator would try to read it with its new handshake state
			// and fail with a bogus "crypto mismatch".
			GlobalSessions.mu.RLock()
			cur := GlobalSessions.pendingByAddr[key]
			GlobalSessions.mu.RUnlock()
			if cur != pending {
				return
			}
			_, _ = conn.WriteToUDP(msg2Frame, addr)
		}
	}

	_, cs1, cs2, err := hs.ReadMessage(nil, payload3)
	if err != nil {
		cleanupPending()
		return
	}

	// Learn the initiator's static key (from msg3) and drop the handshake if
	// this peer has been revoked from the admin dashboard.
	var peerStatic [32]byte
	copy(peerStatic[:], hs.PeerStatic())
	if revoked.isRevoked(peerStatic) || revocations.isRevoked(peerStatic) {
		cleanupPending()
		log.Printf("rejected revoked peer %s", addr)
		return
	}

	// Responder: send with cs2, recv with cs1.
	GlobalSessions.set(addr, &session{
		addr:        addr,
		send:        cs2,
		recv:        cs1,
		established: true,
		lastSeen:    time.Now(),
		peerStatic:  peerStatic,
		createdAt:   time.Now(),
		initiator:   false,
	})
	log.Printf("session established with %s (responder)", addr)

	// Announce our overlay IP immediately so the peer can route to us (and
	// act as our relay) without waiting for the first keepalive.
	if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() && myOverlayIP != "" {
		_ = sendPacket(conn, addr, s, buildAddrAnnounce())
	}

	cleanupPending()
}
