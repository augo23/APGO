package main

// pqheal.go repairs a post-quantum layer that has fallen out of step between
// two peers. Shared verbatim by the desktop client and the mobile core.
//
// THE FAILURE
//
// The ML-KEM layer (pq.go) is keyed per peer KEY and kept while any route to
// that key is up. When a peer restarts — a phone's VPN reconnecting, an app
// update, a container restart — it comes back with no ML-KEM state and a new
// session, usually from a new port, while this node still holds a live route
// to the old process. The old route keeps the old ML-KEM key alive here, so:
//
//   - this node wraps every frame (data AND control) under a key the peer no
//     longer has, and the peer silently drops all of them; and
//   - if this node is the designated offerer, buildPQOffer answers "already
//     established" and never offers again, while the peer, as responder, only
//     waits for an offer.
//
// Nothing times out, because the peer's own frames still decrypt at the Noise
// layer on both ends, so the session looks healthy. The peer never sees this
// node's address announce, keepalives or replies: it keeps sending
// punch-requests, and applications (RustDesk, SSH) connect and then hang.
//
// THE REPAIR
//
// Two signals show a layer is out of step, and both are only ever produced by
// a peer whose state differs from ours:
//
//  1. Frames from the peer that we cannot unwrap (we hold no key, or a
//     different one).
//  2. For the offerer: ordinary (non-negotiation) frames arriving UNWRAPPED
//     from a peer we hold an established key with. A peer holding the same
//     key wraps everything, so a steady stream of classical frames means it
//     has lost the key.
//
// After a few such frames in a row (a straggler or two around a rekey is
// normal), the node drops its own ML-KEM state for that peer. The offerer then
// offers again at once; the responder sends a small classical "renegotiate"
// frame ('j'), which makes the offerer do the same. Actions are rate-limited
// per peer. A peer can only ever reset the layer it shares with us, over its
// own authenticated Noise session.

import (
	"log"
	"net"
	"sync"
	"time"
)

const (
	// pqHealThreshold is how many consecutive out-of-step frames trigger a
	// renegotiation.
	pqHealThreshold = 4
	// pqHealSettle ignores signals for this long after a key is established:
	// frames sent just before the peer switched keys may still be in flight.
	pqHealSettle = 3 * time.Second
	// pqHealMinGap is the minimum time between two repairs for one peer.
	pqHealMinGap = 10 * time.Second
	// pqResetFrame asks the offerer to run a fresh ML-KEM exchange. It is a
	// negotiation frame (never wrapped); older builds ignore it.
	pqResetFrame = 'j'
)

type pqHealPeer struct {
	bad         int
	established time.Time
	lastAction  time.Time
}

var (
	pqHealMu    sync.Mutex
	pqHealPeers = map[[32]byte]*pqHealPeer{}
	pqHealCount uint64 // renegotiations started (exported in stats/tests)
)

func pqHealGet(peer [32]byte) *pqHealPeer {
	h := pqHealPeers[peer]
	if h == nil {
		if len(pqHealPeers) > 4096 {
			pqHealPeers = map[[32]byte]*pqHealPeer{}
		}
		h = &pqHealPeer{}
		pqHealPeers[peer] = h
	}
	return h
}

// pqHealEstablished records that a key was just established with peer.
func pqHealEstablished(peer [32]byte) {
	pqHealMu.Lock()
	h := pqHealGet(peer)
	h.bad = 0
	h.established = time.Now()
	pqHealMu.Unlock()
}

// pqHealOpened records a frame from peer that unwrapped correctly.
func pqHealOpened(peer [32]byte) {
	pqHealMu.Lock()
	if h := pqHealPeers[peer]; h != nil {
		h.bad = 0
	}
	pqHealMu.Unlock()
}

// pqHealUnopenable is called for a wrapped frame from peer that did not open.
func pqHealUnopenable(peer [32]byte, raddr *net.UDPAddr) {
	// Our own offer is in flight: the responder has already switched to the
	// new key and its frames cannot open until its reply reaches us. Normal.
	// (If the reply never comes, the keepalive tick re-sends the offer.)
	if p := pqGet(peer); p != nil && p.aead == nil && p.priv != nil {
		return
	}
	pqHealSignal(peer, raddr, "cannot open its post-quantum frames")
}

// pqHealClassical is called for every UNWRAPPED frame from peer (after Noise
// decryption and decompression).
func pqHealClassical(peer [32]byte, raddr *net.UDPAddr, pt []byte) {
	if !pqEnabled || isPQNegotiation(pt) || !pqInitiator(peer) || !pqReady(peer) {
		return
	}
	pqHealSignal(peer, raddr, "is sending without the post-quantum layer")
}

func pqHealSignal(peer [32]byte, raddr *net.UDPAddr, why string) {
	if !pqEnabled || peer == ([32]byte{}) {
		return
	}
	now := time.Now()
	pqHealMu.Lock()
	h := pqHealGet(peer)
	if now.Sub(h.established) < pqHealSettle {
		pqHealMu.Unlock()
		return
	}
	h.bad++
	if h.bad < pqHealThreshold || now.Sub(h.lastAction) < pqHealMinGap {
		pqHealMu.Unlock()
		return
	}
	h.bad = 0
	h.lastAction = now
	pqHealCount++
	pqHealMu.Unlock()

	log.Printf("[pq] peer %s %s — its post-quantum state no longer matches ours "+
		"(usually the peer restarted); renegotiating", peerKeyFingerprint(peer[:]), why)
	pqForget(peer)
	pqHealKick(peer, raddr)
}

// pqHealKick starts a fresh exchange with peer: the offerer offers now, the
// responder asks the offerer to.
func pqHealKick(peer [32]byte, raddr *net.UDPAddr) {
	if GlobalSessions == nil || GlobalConn == nil || raddr == nil {
		return
	}
	s := GlobalSessions.GetByAddr(raddr)
	if s == nil || !s.Established() || s.peerStatic != peer {
		return
	}
	var frame []byte
	if pqInitiator(peer) {
		frame = buildPQOffer(peer)
	} else {
		// One payload byte (version): control frames shorter than two
		// bytes are discarded by handleControl.
		frame = append(append([]byte(nil), ctlMagic...), pqResetFrame, 1)
	}
	if frame != nil {
		_ = sendPacket(GlobalConn, raddr, s, frame)
	}
}

// pqHealRenegotiations reports how many repairs this node has started.
func pqHealRenegotiations() uint64 {
	pqHealMu.Lock()
	defer pqHealMu.Unlock()
	return pqHealCount
}

// handlePQResetRequest handles a 'j' frame: the peer lost our shared ML-KEM
// key. Only the offerer acts; rate-limited like the other repairs.
func handlePQResetRequest(raddr *net.UDPAddr) {
	if !pqEnabled || GlobalSessions == nil {
		return
	}
	s := GlobalSessions.GetByAddr(raddr)
	if s == nil || !s.Established() || !pqInitiator(s.peerStatic) {
		return
	}
	peer := s.peerStatic
	now := time.Now()
	pqHealMu.Lock()
	h := pqHealGet(peer)
	if now.Sub(h.lastAction) < pqHealMinGap || now.Sub(h.established) < pqHealSettle {
		pqHealMu.Unlock()
		return
	}
	h.bad = 0
	h.lastAction = now
	pqHealCount++
	pqHealMu.Unlock()
	log.Printf("[pq] peer %s lost our post-quantum key (it asked to renegotiate); offering a fresh one",
		peerKeyFingerprint(peer[:]))
	pqForget(peer)
	pqHealKick(peer, raddr)
}
