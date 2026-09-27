package overlaymobile

// e2epq.go — the post-quantum half of end-to-end relay encryption.
//
// WHY THIS NEEDS ITS OWN EXCHANGE
//
// ML-KEM is a key-encapsulation mechanism: to share a secret with a node you
// need that node's ML-KEM public key, and only the holder of the matching
// private key can recover the secret. Nodes have no long-term ML-KEM keys —
// their identity is an X25519 key — so, exactly as on direct sessions (pq.go),
// the two ends run a fresh ML-KEM-768 exchange inside a channel that is
// already authenticated. Here that channel is the classical end-to-end
// envelope (e2erelay.go), so relays carry the exchange but cannot read or
// alter it.
//
// THE EXCHANGE (one per direction, per pair of nodes)
//
//	A -> B  offer:  0x01 | ek                       (A's fresh ML-KEM-768 public key)
//	B -> A  reply:  0x02 | H(ek)[:8] | ct           (encapsulation to ek)
//	A -> B  data :  sealed with DH(eph,B) || DH(A,B) || ss, tagged with id(ss)
//
// Offers and replies travel in classical envelopes (pq id 0). Data never does:
// a relayed data packet is only ever sealed under a key that includes the
// ML-KEM secret, and a receiver refuses relayed data without one. There is no
// fallback, so a relay that drops the exchange gets no traffic, not
// classical-only traffic.
//
// Each direction is independent — A's secret for A->B is the one A's offer
// created — so simultaneous offers from both ends cannot race. Secrets are
// re-established every e2ePQRekey (with a fresh ML-KEM key pair each time,
// which gives the PQ layer forward secrecy too). If B loses its secret (a
// restart), it tells A with a reset, and A runs a new exchange.

import (
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

const (
	e2eKindOffer = 0x01
	e2eKindReply = 0x02
	e2eKindReset = 0x03

	e2ePQRekey        = 30 * time.Minute
	e2ePQRetry        = time.Second
	e2ePQPendingMax   = 30 * time.Second // regenerate an offer nobody answered
	e2ePQKeepOld      = 10 * time.Minute // accept the previous secret this long after a newer one
	e2ePQMaxSecrets   = 4
	e2ePQMaxPeers     = 4096
	e2ePQOffersPerMin = 6
	e2ePQResetGap     = 2 * time.Second
)

var (
	errE2EPQBadReply = errors.New("e2e-pq: reply does not match a pending offer")
	errE2EPQLimit    = errors.New("e2e-pq: offer rate limit")
)

func e2ePQScheme() kem.Scheme { return mlkem768.Scheme() }

type e2ePQSecret struct {
	id   [4]byte
	ss   [32]byte
	born time.Time
}

func newE2EPQSecret(ss []byte, now time.Time) *e2ePQSecret {
	s := &e2ePQSecret{born: now}
	copy(s.ss[:], ss)
	h := sha256.Sum256(append([]byte("apgo-e2e-pq-id-v1:"), ss...))
	copy(s.id[:], h[:4])
	if s.id == ([4]byte{}) {
		s.id[3] = 1 // 0 means "no PQ secret" on the wire
	}
	return s
}

type e2ePQOut struct {
	cur      *e2ePQSecret
	dk       kem.PrivateKey
	ek       []byte
	ekHash   [8]byte
	pendBorn time.Time
	lastSent time.Time
	touched  time.Time
}

type e2ePQIn struct {
	secrets    []*e2ePQSecret // oldest first
	lastEKHash [8]byte
	lastReply  []byte
	offers     []time.Time
	lastReset  time.Time
	touched    time.Time
}

type e2ePQ struct {
	mu  sync.Mutex
	out map[[32]byte]*e2ePQOut
	in  map[[32]byte]*e2ePQIn
}

func newE2EPQ() *e2ePQ {
	return &e2ePQ{out: map[[32]byte]*e2ePQOut{}, in: map[[32]byte]*e2ePQIn{}}
}

func ekHash8(ek []byte) [8]byte {
	var h8 [8]byte
	h := sha256.Sum256(ek)
	copy(h8[:], h[:8])
	return h8
}

func pruneOldest[V any](m map[[32]byte]V, touched func(V) time.Time) {
	var oldestK [32]byte
	var oldestT time.Time
	first := true
	for k, v := range m {
		if t := touched(v); first || t.Before(oldestT) {
			oldestK, oldestT, first = k, t, false
		}
	}
	if !first {
		delete(m, oldestK)
	}
}

// outbound returns the secret to seal data for `to` with (nil if none is
// ready yet) and, when an offer should go out now, its payload.
func (p *e2ePQ) outbound(to [32]byte, now time.Time) (*e2ePQSecret, []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	o := p.out[to]
	if o == nil {
		if len(p.out) >= e2ePQMaxPeers {
			pruneOldest(p.out, func(v *e2ePQOut) time.Time { return v.touched })
		}
		o = &e2ePQOut{}
		p.out[to] = o
	}
	o.touched = now
	cur := o.cur
	needOffer := cur == nil || now.Sub(cur.born) >= e2ePQRekey
	if !needOffer {
		return cur, nil
	}
	if o.dk != nil && now.Sub(o.pendBorn) > e2ePQPendingMax {
		o.dk, o.ek = nil, nil // unanswered: start over with a fresh key pair
	}
	if o.dk == nil {
		pk, sk, err := e2ePQScheme().GenerateKeyPair()
		if err != nil {
			return cur, nil
		}
		ek, err := pk.MarshalBinary()
		if err != nil {
			return cur, nil
		}
		o.dk, o.ek, o.ekHash, o.pendBorn = sk, ek, ekHash8(ek), now
		o.lastSent = time.Time{}
	}
	if !o.lastSent.IsZero() && now.Sub(o.lastSent) < e2ePQRetry {
		return cur, nil
	}
	o.lastSent = now
	offer := make([]byte, 0, 1+len(o.ek))
	offer = append(append(offer, e2eKindOffer), o.ek...)
	return cur, offer
}

// onOffer (receiver of an offer from `from`) encapsulates to the offered key,
// stores the resulting secret as valid for data from `from`, and returns the
// reply payload. A repeated offer gets the same reply.
func (p *e2ePQ) onOffer(from [32]byte, ek []byte, now time.Time) ([]byte, error) {
	h8 := ekHash8(ek)
	p.mu.Lock()
	in := p.in[from]
	if in != nil && in.lastReply != nil && in.lastEKHash == h8 {
		reply := append([]byte(nil), in.lastReply...)
		in.touched = now
		p.mu.Unlock()
		return reply, nil
	}
	if in != nil {
		recent := in.offers[:0]
		for _, t := range in.offers {
			if now.Sub(t) < time.Minute {
				recent = append(recent, t)
			}
		}
		in.offers = recent
		if len(in.offers) >= e2ePQOffersPerMin {
			p.mu.Unlock()
			return nil, errE2EPQLimit
		}
	}
	p.mu.Unlock()

	sch := e2ePQScheme()
	if len(ek) != sch.PublicKeySize() {
		return nil, errE2EAuth
	}
	pk, err := sch.UnmarshalBinaryPublicKey(ek)
	if err != nil {
		return nil, err
	}
	ct, ss, err := sch.Encapsulate(pk)
	if err != nil {
		return nil, err
	}
	sec := newE2EPQSecret(ss, now)
	reply := make([]byte, 0, 1+8+len(ct))
	reply = append(append(append(reply, e2eKindReply), h8[:]...), ct...)

	p.mu.Lock()
	defer p.mu.Unlock()
	in = p.in[from]
	if in == nil {
		if len(p.in) >= e2ePQMaxPeers {
			pruneOldest(p.in, func(v *e2ePQIn) time.Time { return v.touched })
		}
		in = &e2ePQIn{}
		p.in[from] = in
	}
	in.touched = now
	in.offers = append(in.offers, now)
	in.lastEKHash, in.lastReply = h8, append([]byte(nil), reply...)
	in.secrets = append(in.secrets, sec)
	if len(in.secrets) > e2ePQMaxSecrets {
		in.secrets = in.secrets[len(in.secrets)-e2ePQMaxSecrets:]
	}
	return reply, nil
}

// onReply (offerer) completes the exchange with `from`.
func (p *e2ePQ) onReply(from [32]byte, body []byte, now time.Time) error {
	sch := e2ePQScheme()
	if len(body) != 8+sch.CiphertextSize() {
		return errE2EPQBadReply
	}
	p.mu.Lock()
	o := p.out[from]
	if o == nil || o.dk == nil || string(o.ekHash[:]) != string(body[:8]) {
		p.mu.Unlock()
		return errE2EPQBadReply
	}
	dk := o.dk
	p.mu.Unlock()
	ss, err := sch.Decapsulate(dk, body[8:])
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if o = p.out[from]; o == nil || o.dk != dk {
		return errE2EPQBadReply // superseded meanwhile
	}
	o.cur = newE2EPQSecret(ss, now)
	o.dk, o.ek, o.lastSent = nil, nil, time.Time{}
	o.touched = now
	return nil
}

// secretFor returns the secret `from` tagged a data packet with, if still valid.
func (p *e2ePQ) secretFor(from [32]byte, id [4]byte, now time.Time) *[32]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	in := p.in[from]
	if in == nil {
		return nil
	}
	n := len(in.secrets)
	for i, s := range in.secrets {
		if s.id != id {
			continue
		}
		// The newest secret is always valid; an older one only until the
		// newer has been in use for e2ePQKeepOld (in-flight packets).
		if i < n-1 && now.Sub(in.secrets[i+1].born) > e2ePQKeepOld {
			return nil
		}
		in.touched = now
		ss := s.ss
		return &ss
	}
	return nil
}

// onReset (offerer) drops the secret `from` no longer holds.
func (p *e2ePQ) onReset(from [32]byte, id [4]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if o := p.out[from]; o != nil && o.cur != nil && o.cur.id == id {
		o.cur = nil
	}
}

// shouldReset rate-limits resets sent to `to`.
func (p *e2ePQ) shouldReset(to [32]byte, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	in := p.in[to]
	if in == nil {
		if len(p.in) >= e2ePQMaxPeers {
			pruneOldest(p.in, func(v *e2ePQIn) time.Time { return v.touched })
		}
		in = &e2ePQIn{touched: now}
		p.in[to] = in
	}
	if now.Sub(in.lastReset) < e2ePQResetGap {
		return false
	}
	in.lastReset = now
	return true
}

func resetPayload(id [4]byte) []byte {
	return append([]byte{e2eKindReset}, id[:]...)
}
