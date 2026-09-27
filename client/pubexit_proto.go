package main

// pubexit_proto.go — the wire protocol of PUBLIC EXIT NODES, shared verbatim
// by the desktop client (which can serve and use public exits) and the mobile
// core (which can only use them).
//
// WHAT A PUBLIC EXIT IS
//
// An internal exit node (exit.go) forwards the internet traffic of devices
// admitted to ITS OWN overlay network. A public exit node shares its internet
// connection with any APGO user — people who are not members of its network,
// hold none of its keys, and are found through the same public directories as
// public relays (the DHT and BitTorrent trackers).
//
// ISOLATION IS STRUCTURAL
//
// A stranger never touches the overlay. Public-exit traffic uses its own
// transport type byte (PktPubExit), its own handshake (no network PSK — a
// stranger cannot have it), its own keys and its own session table. Nothing
// in this protocol is ever handed to the overlay's session, routing, control
// or relay code, so a public-exit client cannot:
//
//   - reach overlay members, the exit's LAN, or the exit host itself — every
//     packet it sends is checked by pxAllowedDestination and only PUBLIC
//     internet addresses pass;
//   - spoof anything — the exit overwrites the source address of every packet
//     with an address from a private pool it assigned to that client;
//   - read or inject overlay traffic, gossip, provisions or approvals — those
//     live on a different packet type the exit never accepts from it.
//
// CRYPTOGRAPHY
//
// Noise XX (X25519, ChaCha20-Poly1305, SHA-256) under a public-exit prologue,
// combined with an ML-KEM-768 encapsulation carried inside the handshake, so
// the session is protected if EITHER X25519 or ML-KEM holds ("harvest now,
// decrypt later" resistant). Transport keys are derived from both. Clients
// use a fresh static key per exit session, so an exit cannot link one
// person's sessions or tie them to the person's overlay identity.
//
// There is no PSK and no pre-shared exit key: a stranger's exit is found in a
// public directory, so the exit's identity is not something a client could
// verify anyway. Whoever answers is, by definition, the exit — and an exit
// can see where its clients' traffic goes, like any VPN provider. Use TLS.
//
// ANTI-ABUSE
//
// The first handshake message is padded to pxHelloSize and every reply is
// smaller, so a spoofed hello cannot be used for amplification. Hellos are
// rate-limited globally and per source address before any expensive work.

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/flynn/noise"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// PktPubExit is the transport type byte for public-exit datagrams. It is
// outside the overlay range (0x01-0x05), the public relay (0x10), STUN and
// the DHT ('d'), so all of them share the one UDP socket unambiguously.
const PktPubExit byte = 0x20

// Outer (cleartext) message types.
const (
	pxHello      byte = 0x01 // client -> exit: Noise msg1 + ML-KEM public key, padded
	pxHelloReply byte = 0x02 // exit -> client: session id + Noise msg2 (+ ML-KEM ciphertext)
	pxFinish     byte = 0x03 // client -> exit: Noise msg3
	pxData       byte = 0x04 // both ways: sealed inner message
	pxDeny       byte = 0x05 // exit -> client: refusal reason (unauthenticated, advisory)
)

// Inner (sealed) message kinds.
const (
	pxInPacket byte = 0x01 // an IPv4 packet
	pxInPing   byte = 0x02 // liveness probe (echoed)
	pxInPong   byte = 0x03
	pxInAssign byte = 0x04 // exit -> client: [pool ip 4][mtu 2][lease seconds 4]
	pxInClose  byte = 0x05 // either side: session ends
)

// Deny reasons.
const (
	pxDenyDisabled byte = 1
	pxDenyFull     byte = 2
	pxDenyQuota    byte = 3
	pxDenyRate     byte = 4
	pxDenyVersion  byte = 5
)

const (
	pxVersion byte = 1
	// pxHelloSize: every hello is exactly this long, and no reply to it is
	// longer (HelloReply ≈ 1210 bytes, Deny 3 bytes).
	pxHelloSize = 1400
	pxHdrLen    = 2 + 4 + 8 // type, sub, session id, counter
	// pxMTU is the inner MTU offered to clients: 1280 (the overlay default)
	// already leaves room for the ~50 bytes of framing here.
	pxMTU = 1280
	// pxLease bounds a session's life; the client re-handshakes before it
	// ends, which also rotates every key.
	pxLease = 6 * time.Hour
	// pxHandshakeTTL is how long an exit keeps a half-finished handshake.
	pxHandshakeTTL = 10 * time.Second
	// pxIdle ends a session nobody has used.
	pxIdle = 3 * time.Minute
)

var pxPrologue = []byte("apgo-public-exit-v1")

// pxDirectoryKey is the DHT / tracker key public exits advertise under.
// Deliberately public and unblinded, like the public relay directory: being a
// public exit is an announcement to everyone.
func pxDirectoryKey() []byte {
	h := sha256.Sum256([]byte("apgo-public-exit-directory-v1"))
	return h[:20]
}

var (
	errPxShort = errors.New("public exit: short message")
	errPxAuth  = errors.New("public exit: authentication failed")
	errPxRepl  = errors.New("public exit: replayed or too-old packet")
)

func pxScheme() kem.Scheme { return mlkem768.Scheme() }

func pxNoiseConfig(initiator bool, static noise.DHKey) noise.Config {
	return noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       noise.HandshakeXX,
		Initiator:     initiator,
		StaticKeypair: static,
		Prologue:      pxPrologue,
		Random:        rand.Reader,
	}
}

func pxNewStatic() (noise.DHKey, error) {
	return noise.DH25519.GenerateKeypair(rand.Reader)
}

// pxDeriveKeys combines the Noise transport keys with the ML-KEM secret. The
// result is secure if either the X25519 exchange or ML-KEM is.
func pxDeriveKeys(initiator bool, c2s, s2c *noise.CipherState, binding, pqss []byte) (send, recv cipher.AEAD, err error) {
	derive := func(cs *noise.CipherState, label string) (cipher.AEAD, error) {
		k := cs.UnsafeKey()
		secret := make([]byte, 0, len(pqss)+32)
		secret = append(append(secret, pqss...), k[:]...)
		key := make([]byte, chacha20poly1305.KeySize)
		if _, err := io.ReadFull(hkdf.New(sha256.New, secret, binding, []byte(label)), key); err != nil {
			return nil, err
		}
		return chacha20poly1305.New(key)
	}
	a, err := derive(c2s, "apgo-public-exit-v1 client->exit")
	if err != nil {
		return nil, nil, err
	}
	b, err := derive(s2c, "apgo-public-exit-v1 exit->client")
	if err != nil {
		return nil, nil, err
	}
	if initiator {
		return a, b, nil
	}
	return b, a, nil
}

// pxChannel is one direction pair of a session: sealing with a monotonic
// counter, opening with a replay window.
type pxChannel struct {
	sid  uint32
	send cipher.AEAD
	recv cipher.AEAD

	sendMu  sync.Mutex
	sendCtr uint64

	recvMu sync.Mutex
	win    e2eWindow
}

func pxNonce(ctr uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n
}

// seal returns a complete pxData datagram carrying kind+body.
func (c *pxChannel) seal(kind byte, body []byte) []byte {
	c.sendMu.Lock()
	c.sendCtr++
	ctr := c.sendCtr
	c.sendMu.Unlock()
	out := make([]byte, pxHdrLen, pxHdrLen+1+len(body)+chacha20poly1305.Overhead)
	out[0], out[1] = PktPubExit, pxData
	binary.BigEndian.PutUint32(out[2:6], c.sid)
	binary.BigEndian.PutUint64(out[6:14], ctr)
	pt := make([]byte, 0, 1+len(body))
	pt = append(append(pt, kind), body...)
	return c.send.Seal(out, pxNonce(ctr), pt, out[:pxHdrLen])
}

// open authenticates a pxData datagram (already known to belong to this
// session) and returns its kind and body.
func (c *pxChannel) open(dgram []byte) (byte, []byte, error) {
	if len(dgram) < pxHdrLen+1+chacha20poly1305.Overhead {
		return 0, nil, errPxShort
	}
	ctr := binary.BigEndian.Uint64(dgram[6:14])
	c.recvMu.Lock()
	fresh := c.win.ok(ctr)
	c.recvMu.Unlock()
	if !fresh {
		return 0, nil, errPxRepl
	}
	pt, err := c.recv.Open(nil, pxNonce(ctr), dgram[pxHdrLen:], dgram[:pxHdrLen])
	if err != nil || len(pt) < 1 {
		return 0, nil, errPxAuth
	}
	c.recvMu.Lock()
	ok := c.win.ok(ctr)
	if ok {
		c.win.mark(ctr)
	}
	c.recvMu.Unlock()
	if !ok {
		return 0, nil, errPxRepl
	}
	return pt[0], pt[1:], nil
}

func pxSessionID(dgram []byte) (uint32, bool) {
	if len(dgram) < 6 {
		return 0, false
	}
	return binary.BigEndian.Uint32(dgram[2:6]), true
}

// --- event rate limiter (counts, not bytes) -----------------------------------

type pxRate struct {
	mu     sync.Mutex
	rate   float64 // events per second
	burst  float64
	tokens float64
	last   time.Time
}

func newPxRate(perSec, burst float64) *pxRate {
	return &pxRate{rate: perSec, burst: burst, tokens: burst, last: time.Now()}
}

func (r *pxRate) allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	r.tokens += now.Sub(r.last).Seconds() * r.rate
	r.last = now
	if r.tokens > r.burst {
		r.tokens = r.burst
	}
	if r.tokens < 1 {
		return false
	}
	r.tokens--
	return true
}

// --- IPv4 inspection and rewriting ------------------------------------------

type pxIPv4 struct {
	ihl      int
	proto    byte
	src, dst [4]byte
	firstFrg bool // fragment offset 0 (L4 header present)
	dport    uint16
	hasPort  bool
	icmpType byte
	tcpFlags byte
}

// pxParse validates the IPv4 framing of pkt (no options trickery, sane
// lengths) and extracts what the filter needs.
func pxParse(pkt []byte) (pxIPv4, bool) {
	var p pxIPv4
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return p, false
	}
	p.ihl = int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if p.ihl < 20 || total < p.ihl || total != len(pkt) {
		return p, false
	}
	p.proto = pkt[9]
	copy(p.src[:], pkt[12:16])
	copy(p.dst[:], pkt[16:20])
	p.firstFrg = binary.BigEndian.Uint16(pkt[6:8])&0x1fff == 0
	if !p.firstFrg {
		return p, true
	}
	l4 := pkt[p.ihl:]
	switch p.proto {
	case 6: // TCP
		if len(l4) < 20 {
			return p, false
		}
		p.dport = binary.BigEndian.Uint16(l4[2:4])
		p.hasPort = true
		p.tcpFlags = l4[13]
	case 17: // UDP
		if len(l4) < 8 {
			return p, false
		}
		p.dport = binary.BigEndian.Uint16(l4[2:4])
		p.hasPort = true
	case 1: // ICMP
		if len(l4) < 8 {
			return p, false
		}
		p.icmpType = l4[0]
	}
	return p, true
}

// pxNonPublic lists every IPv4 range that is not the public internet.
var pxNonPublic = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/3", // multicast + reserved + broadcast
	} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// pxIsPublicIPv4 reports whether ip is an ordinary public unicast address.
func pxIsPublicIPv4(ip [4]byte) bool {
	a := net.IP(ip[:])
	for _, n := range pxNonPublic {
		if n.Contains(a) {
			return false
		}
	}
	return true
}

func pxChecksum(b []byte) uint16 {
	var s uint32
	for len(b) >= 2 {
		s += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		s += uint32(b[0]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

// pxAdjust updates a one's-complement checksum field for an address change
// (RFC 1624, eqn. 3).
func pxAdjust(field []byte, old, new [4]byte) {
	sum := uint32(^binary.BigEndian.Uint16(field))
	for i := 0; i < 4; i += 2 {
		sum += uint32(^(uint16(old[i])<<8 | uint16(old[i+1])))
		sum += uint32(uint16(new[i])<<8 | uint16(new[i+1]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(field, ^uint16(sum))
}

// pxRewrite replaces the source (src=true) or destination address of an IPv4
// packet in place, fixing the IP header checksum and the TCP/UDP checksum
// (whose pseudo-header covers the addresses). For ICMP errors travelling TO
// a client, the quoted inner header is rewritten too, so the client's stack
// can match the error (path-MTU discovery keeps working).
func pxRewrite(pkt []byte, src bool, addr [4]byte) bool {
	p, ok := pxParse(pkt)
	if !ok {
		return false
	}
	off := 16
	old := p.dst
	if src {
		off, old = 12, p.src
	}
	if old == addr {
		return true
	}
	copy(pkt[off:off+4], addr[:])
	pkt[10], pkt[11] = 0, 0
	binary.BigEndian.PutUint16(pkt[10:12], pxChecksum(pkt[:p.ihl]))
	if !p.firstFrg {
		return true
	}
	l4 := pkt[p.ihl:]
	switch p.proto {
	case 6:
		pxAdjust(l4[16:18], old, addr)
	case 17:
		if l4[6] != 0 || l4[7] != 0 { // zero = no checksum (IPv4)
			pxAdjust(l4[6:8], old, addr)
			if l4[6] == 0 && l4[7] == 0 {
				l4[6], l4[7] = 0xff, 0xff
			}
		}
	case 1:
		if !src && (p.icmpType == 3 || p.icmpType == 11 || p.icmpType == 12) && len(l4) >= 8+20 {
			inner := l4[8:]
			if inner[0]>>4 == 4 {
				ihl := int(inner[0]&0x0f) * 4
				if ihl >= 20 && len(inner) >= ihl {
					var in [4]byte
					copy(in[:], inner[12:16])
					if in == old {
						copy(inner[12:16], addr[:])
						inner[10], inner[11] = 0, 0
						binary.BigEndian.PutUint16(inner[10:12], pxChecksum(inner[:ihl]))
						// The quoted transport header is truncated; its
						// checksum is not verified by receivers.
					}
				}
			}
			l4[2], l4[3] = 0, 0
			binary.BigEndian.PutUint16(l4[2:4], pxChecksum(l4))
		}
	}
	return true
}
