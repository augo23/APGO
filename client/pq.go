package main

// pq.go adds OPTIONAL post-quantum protection. It is a HYBRID: the classical
// Noise XX (X25519 + ChaCha20/AES-GCM) tunnel is unchanged, and on top of it —
// only when both peers enable post_quantum — we run an ML-KEM-768 (Kyber, NIST
// FIPS 203) key encapsulation INSIDE the already-authenticated Noise channel and
// wrap each direct data packet in a second ChaCha20-Poly1305 layer keyed by the
// ML-KEM shared secret.
//
// Why this shape:
//   - The ML-KEM public key + ciphertext travel inside the classically encrypted
//     & authenticated Noise session, so a man-in-the-middle can't tamper with the
//     PQ exchange (authentication is inherited from Noise's static keys).
//   - Confidentiality of the payload then survives a future quantum computer that
//     breaks X25519 ("harvest now, decrypt later" resistance): the attacker still
//     faces ML-KEM.
//   - It's hybrid, so you're safe if EITHER primitive holds.
//
// Cost: one ML-KEM handshake per peer at connect (sub-millisecond) plus a second
// AEAD per packet and ~40 bytes of overhead (so lower the tunnel MTU a little —
// see the README). PQ engages only on DIRECT peer sessions; relayed/exit traffic
// stays classical.

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"log"
	"sync"
	"sync/atomic"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// pqEnabled is set from config (post_quantum: true). When false, none of this
// code path is exercised and the wire is byte-for-byte classical.
var pqEnabled bool

// pqMagic prefixes a PQ-wrapped data packet (after Noise decryption). It shares
// the "OVLY" family prefix but is distinct from ctlMagic ("OVLYCTL1"); it is
// always tested with HasPrefix BEFORE the IPv4 check.
var pqMagic = []byte("OVLYPQ1\x00")

type pqPeer struct {
	aead     cipher.AEAD    // ready once the ML-KEM secret is derived

	// Nonce sequence for this key: a random per-key salt plus a monotonic
	// counter, the standard AEAD record construction. It replaces a
	// crypto/rand read PER PACKET — a getentropy syscall on every single
	// datagram, which on a phone is both a syscall storm and (via the
	// allocation it needed) GC pressure. Uniqueness is what matters for
	// AEAD safety, not unpredictability, and salt+counter guarantees it:
	// the counter is per-key (a fresh pqPeer is built for every new aead,
	// below) and 2^64 packets is unreachable. The nonce still travels on
	// the wire, so this is wire-compatible with peers using the old
	// random-nonce build.
	nonceSalt [4]byte
	nonceCtr  atomic.Uint64

	priv     kem.PrivateKey // initiator: kept until the responder's ciphertext arrives
	offerPKB []byte         // initiator: cached marshaled offer pubkey, so RETRANSMITS reuse the same keypair (a reply to any earlier offer still decapsulates)

	// Responder-side idempotence. With MULTIPLE ROUTES to one peer the same
	// offer arrives once per route (plus 1.5s re-offer retransmits while the
	// reply is in flight). Re-encapsulating on every copy derived a FRESH key
	// each time while the initiator locked in whichever reply landed first —
	// the two ends held DIFFERENT PQ keys, every wrapped packet failed to
	// open, and the layer never converged (repeated "established" log spam).
	// Cache the reply per offer pubkey and resend the SAME ciphertext for
	// duplicate offers.
	offerHash [32]byte // sha256 of the offer pubkey this state answers
	replyCT   []byte   // the encapsulation ciphertext we replied with
}

var (
	pqMu    sync.RWMutex
	pqPeers = map[[32]byte]*pqPeer{}
)

// newPQPeer builds the per-peer PQ state for a freshly derived key. Going
// through here (rather than a bare &pqPeer{aead: ...}) is what guarantees the
// nonce counter restarts from zero against a NEW salt every time the key
// changes — the one way a counter-based nonce could ever repeat.
func newPQPeer(aead cipher.AEAD) *pqPeer {
	p := &pqPeer{aead: aead}
	if _, err := rand.Read(p.nonceSalt[:]); err != nil {
		// Salt is defence in depth; the counter alone is already unique
		// per key. A zero salt is safe, so never fail the handshake here.
		p.nonceSalt = [4]byte{}
	}
	return p
}

// nextNonce writes this peer's next unique nonce into dst (12 bytes for
// ChaCha20-Poly1305) and returns it.
func (p *pqPeer) nextNonce(dst []byte) []byte {
	copy(dst[:4], p.nonceSalt[:])
	binary.BigEndian.PutUint64(dst[4:12], p.nonceCtr.Add(1))
	return dst
}

// pqWrapPool recycles the buffer pqWrapTo builds into, so the PQ layer stops
// allocating a fresh frame for every outbound packet.
var pqWrapPool = sync.Pool{New: func() any { b := make([]byte, maxFrameSize); return &b }}

func pqScheme() kem.Scheme { return mlkem768.Scheme() }

// pqInitiator reports whether WE are the designated PQ offerer for this peer:
// the side with the lexicographically smaller static key. The offer role used
// to follow the Noise session's initiator role — but with multiple routes to
// one peer the roles can differ per route, so BOTH ends offered and BOTH also
// answered as responder, overwriting their own pending state with a second,
// different key. A key-order tiebreak gives every pair exactly one offerer.
func pqInitiator(peer [32]byte) bool {
	return bytes.Compare(gKP.pub[:], peer[:]) < 0
}

// pqGet runs per-packet on the hot path, so it takes only a read lock; the map
// is written rarely (once per peer, during PQ negotiation).
func pqGet(pub [32]byte) *pqPeer {
	pqMu.RLock()
	defer pqMu.RUnlock()
	return pqPeers[pub]
}

func pqReady(pub [32]byte) bool {
	p := pqGet(pub)
	return p != nil && p.aead != nil
}

func pqAEADFromSecret(ss []byte) (cipher.AEAD, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	r := hkdf.New(sha256.New, ss, nil, []byte("apgo-pq-v1"))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return chacha20poly1305.New(key)
}

// buildPQOffer (initiator) generates a fresh ML-KEM keypair and returns an
// "OVLYCTL1M<pubkey>" control frame, remembering the private key for this peer.
func buildPQOffer(peer [32]byte) []byte {
	if !pqEnabled {
		return nil
	}
	// Idempotent: resend the SAME public key on retransmit instead of a fresh
	// keypair. Regenerating each time raced with in-flight replies (a reply to an
	// earlier offer decapsulated against a newer key and silently failed), so the
	// quantum-safe lock could take many retries to converge.
	pqMu.Lock()
	if p := pqPeers[peer]; p != nil {
		if p.aead != nil {
			pqMu.Unlock()
			return nil // already established
		}
		if p.priv != nil && p.offerPKB != nil {
			out := append(append([]byte(nil), ctlMagic...), 'M')
			out = append(out, p.offerPKB...)
			pqMu.Unlock()
			return out
		}
	}
	pqMu.Unlock()

	sch := pqScheme()
	pk, sk, err := sch.GenerateKeyPair()
	if err != nil {
		return nil
	}
	pkb, err := pk.MarshalBinary()
	if err != nil {
		return nil
	}
	pqMu.Lock()
	pqPeers[peer] = &pqPeer{priv: sk, offerPKB: pkb}
	pqMu.Unlock()

	out := append([]byte(nil), ctlMagic...)
	out = append(out, 'M')
	return append(out, pkb...)
}

// handlePQOffer (responder) encapsulates against the offered public key, derives
// the AEAD, and returns an "OVLYCTL1m<ciphertext>" reply frame.
func handlePQOffer(peer [32]byte, pkb []byte) []byte {
	if !pqEnabled {
		return nil
	}
	// Duplicate of an offer we already answered (second route / retransmit):
	// resend the SAME ciphertext, keep the SAME key. Never re-encapsulate —
	// that forks the key between the two ends (see pqPeer).
	h := sha256.Sum256(pkb)
	pqMu.Lock()
	if p := pqPeers[peer]; p != nil && p.aead != nil && p.offerHash == h && p.replyCT != nil {
		out := append(append([]byte(nil), ctlMagic...), 'm')
		out = append(out, p.replyCT...)
		pqMu.Unlock()
		return out
	}
	pqMu.Unlock()

	sch := pqScheme()
	pk, err := sch.UnmarshalBinaryPublicKey(pkb)
	if err != nil {
		return nil
	}
	ct, ss, err := sch.Encapsulate(pk)
	if err != nil {
		return nil
	}
	aead, err := pqAEADFromSecret(ss)
	if err != nil {
		return nil
	}
	pqMu.Lock()
	np := newPQPeer(aead)
	np.offerHash, np.replyCT = h, append([]byte(nil), ct...)
	pqPeers[peer] = np
	pqMu.Unlock()
	log.Printf("[pq] post-quantum layer established with %s (responder)", peerKeyFingerprint(peer[:]))

	out := append([]byte(nil), ctlMagic...)
	out = append(out, 'm')
	return append(out, ct...)
}

// handlePQReply (initiator) decapsulates the responder's ciphertext and derives
// the AEAD.
func handlePQReply(peer [32]byte, ct []byte) {
	pqMu.Lock()
	p := pqPeers[peer]
	pqMu.Unlock()
	if p == nil || p.priv == nil {
		return
	}
	ss, err := pqScheme().Decapsulate(p.priv, ct)
	if err != nil {
		return
	}
	aead, err := pqAEADFromSecret(ss)
	if err != nil {
		return
	}
	pqMu.Lock()
	pqPeers[peer] = newPQPeer(aead)
	pqMu.Unlock()
	log.Printf("[pq] post-quantum layer established with %s (initiator)", peerKeyFingerprint(peer[:]))
}

// pqWrap wraps an inner IPv4 packet for a PQ-ready peer, or returns (nil,false)
// if PQ isn't ready (caller then sends the packet classically).
func pqWrap(peer [32]byte, pkt []byte) ([]byte, bool) {
	return pqWrapTo(nil, peer, pkt)
}

// pqWrapTo is pqWrap writing into a caller-supplied buffer. The hot path hands
// it a pooled buffer so wrapping allocates nothing: the old version allocated
// the nonce, the magic prefix, and then grew that prefix twice inside Seal —
// four allocations and a getentropy syscall on EVERY datagram. At speedtest
// rates that is tens of thousands of allocations a second, which on iOS (where
// the extension runs under a hard ~50 MB cap, so the runtime is pinned to a
// 30 MB soft limit) drives the GC into back-to-back collections and stalls the
// transfer. dst may be nil, in which case this allocates like before.
func pqWrapTo(dst []byte, peer [32]byte, pkt []byte) ([]byte, bool) {
	p := pqGet(peer)
	if p == nil || p.aead == nil {
		return nil, false
	}
	ns := p.aead.NonceSize()
	need := len(pqMagic) + ns + len(pkt) + p.aead.Overhead()
	if cap(dst) < need {
		dst = make([]byte, 0, need)
	}
	out := append(dst[:0], pqMagic...)
	// Extend into the capacity we just guaranteed rather than appending a
	// freshly made slice — that would reintroduce a per-packet allocation.
	// The bytes are stale, which is fine: nextNonce overwrites all of them.
	out = out[:len(pqMagic)+ns]
	nonce := out[len(pqMagic):]
	p.nextNonce(nonce)
	return p.aead.Seal(out, nonce, pkt, nil), true
}

// pqUnwrap opens a PQ-wrapped packet (pt already has the pqMagic prefix).
func pqUnwrap(peer [32]byte, pt []byte) ([]byte, bool) {
	p := pqGet(peer)
	if p == nil || p.aead == nil {
		return nil, false
	}
	body := pt[len(pqMagic):]
	ns := p.aead.NonceSize()
	if len(body) < ns {
		return nil, false
	}
	nonce, ct := body[:ns], body[ns:]
	// Decrypt IN PLACE (dst == ct[:0]): the AEAD writes the plaintext back
	// over the ciphertext instead of allocating a fresh buffer per packet.
	// Safe because pt already aliases the receive buffer — the caller's
	// existing contract — and we only overwrite bytes we have consumed.
	pkt, err := p.aead.Open(ct[:0], nonce, ct, nil)
	if err != nil {
		return nil, false
	}
	return pkt, true
}

// pqForget drops all ML-KEM state for a peer, so the NEXT time a session to it
// forms the layer is renegotiated from scratch. This MUST be called when the
// last route to a peer is torn down. Without it, a stale established-PQ entry
// (aead != nil) makes buildPQOffer short-circuit with "already established" —
// so if the peer restarts and reconnects as the RESPONDER, the initiator never
// re-offers and the responder only ever waits, leaving PQ permanently stuck
// off for a pair that previously had it (and mis-wrapping data under a dead
// key). Clearing on teardown makes both sides start clean and reconverge.
func pqForget(peer [32]byte) {
	pqMu.Lock()
	delete(pqPeers, peer)
	pqMu.Unlock()
}

func isPQPacket(pt []byte) bool { return bytes.HasPrefix(pt, pqMagic) }

// isPQNegotiation reports whether payload is a PQ key-exchange control frame
// ('M' offer or 'm' reply). These must NEVER be PQ-wrapped — they bootstrap the
// layer, so they have to travel classically inside the Noise tunnel.
func isPQNegotiation(payload []byte) bool {
	n := len(ctlMagic)
	return len(payload) > n && bytes.HasPrefix(payload, ctlMagic) && (payload[n] == 'M' || payload[n] == 'm')
}
