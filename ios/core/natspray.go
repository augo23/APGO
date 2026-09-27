package overlaymobile

// natspray.go — the phone's half of the traversal in client/natspray.go.
//
// The pairing that file exists for is symmetric on one side and port-restricted
// on the other, and the work is split between them: the symmetric side opens
// many NAT mappings toward its peer, the restricted side probes many ports to
// find one. A phone is almost always the restricted side of that pair (its own
// carrier NAT is the symmetric one only on mobile data, where punching already
// works), so this core carries the PROBING half only:
//
//   - it sprays probes at a symmetric peer's public address, and
//   - when one is answered, it hands the live endpoint to the ordinary punch.
//
// The mapping-opening half needs a pool of auxiliary sockets and a receive
// path on each of them; that belongs on the servers and desktops that are
// actually behind the randomising NAT (a Kubernetes pod, most often). Leaving
// it out here keeps the tunnel extension's socket budget and battery cost
// where they were, and costs nothing: a phone that IS the symmetric side
// behaves exactly as it does today, which is to relay.
//
// The wire format is shared with the desktop client verbatim — control frame
// "OVLYCTL1" + 'y' + kind + nonce(8) + mac(8), the MAC keyed by the network
// PSK — so either side may be running either implementation.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	natSprayLetter = 'y'
	sprayProbe     = byte(1)
	sprayReply     = byte(2)
	sprayFrameLen  = 1 + 1 + 8 + 8

	natSprayPorts  = 1024
	natSprayPortLo = 1024
	natSprayPortHi = 65535

	natSprayRounds   = 6
	natSprayGap      = 2 * time.Second
	natSprayCooldown = 3 * time.Minute

	natSprayMaxPeers    = 2
	natSprayReplyPerSec = 200
)

// Off unless the node opts in — see client/natspray.go for why this does not
// default to on.
var natSprayEnabled atomic.Bool

func init() { natSprayEnabled.Store(false) }

func sprayMAC(psk []byte, kind byte, nonce []byte) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write([]byte("apgo-natspray-v1"))
	m.Write([]byte{kind})
	m.Write(nonce)
	return m.Sum(nil)[:8]
}

func buildSprayFrame(psk []byte, kind byte, nonce []byte) []byte {
	f := make([]byte, 0, len(ctlMagic)+sprayFrameLen)
	f = append(f, ctlMagic...)
	f = append(f, natSprayLetter, kind)
	f = append(f, nonce...)
	return append(f, sprayMAC(psk, kind, nonce)...)
}

func parseSprayFrame(body, psk []byte) (byte, []byte, bool) {
	if len(body) != sprayFrameLen || body[0] != natSprayLetter {
		return 0, nil, false
	}
	kind, nonce, mac := body[1], body[2:10], body[10:18]
	if kind != sprayProbe && kind != sprayReply {
		return 0, nil, false
	}
	if !hmac.Equal(mac, sprayMAC(psk, kind, nonce)) {
		return 0, nil, false
	}
	return kind, nonce, true
}

var sprayReplyBudget = newSprayRate(natSprayReplyPerSec)

// isNATSprayDatagram recognises a spray frame on the wire. These are PLAINTEXT
// datagrams, not session payloads — the point is to be understood by a node we
// have no session with — so they are demuxed with the other raw frame types,
// never through the control-frame path, which only sees decrypted payloads.
func isNATSprayDatagram(pkt []byte) bool {
	return len(pkt) == len(ctlMagic)+sprayFrameLen &&
		string(pkt[:len(ctlMagic)]) == string(ctlMagic) &&
		pkt[len(ctlMagic)] == natSprayLetter
}

func handleNATSprayDatagram(pkt []byte, raddr *net.UDPAddr) {
	if isNATSprayDatagram(pkt) {
		handleNATSprayFrame(pkt[len(ctlMagic):], raddr)
	}
}

// handleNATSprayFrame answers a probe (a peer guessed this node's mapping) or
// acts on a reply (our own spray found the peer's).
func handleNATSprayFrame(body []byte, raddr *net.UDPAddr) {
	kind, nonce, ok := parseSprayFrame(body, gPSK)
	if !ok || raddr == nil || GlobalConn == nil {
		return
	}
	switch kind {
	case sprayProbe:
		if !sprayReplyBudget.allow() {
			return
		}
		_, _ = GlobalConn.WriteToUDP(buildSprayFrame(gPSK, sprayReply, nonce), raddr)
	case sprayReply:
		gNATSpray.found(raddr)
	}
}

// ------------------------------------------------------------------ rate

type sprayRate struct {
	mu     sync.Mutex
	tokens float64
	rate   float64
	last   time.Time
}

func newSprayRate(perSec float64) *sprayRate {
	return &sprayRate{tokens: perSec, rate: perSec, last: time.Now()}
}

func (r *sprayRate) allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	r.tokens += now.Sub(r.last).Seconds() * r.rate
	r.last = now
	if r.tokens > r.rate {
		r.tokens = r.rate
	}
	if r.tokens < 1 {
		return false
	}
	r.tokens--
	return true
}

// ------------------------------------------------------------------ manager

type sprayAttempt struct {
	overlayIP string
	peerIP    string
	stop      chan struct{}
	done      atomic.Bool
}

type natSprayer struct {
	mu      sync.Mutex
	active  map[string]*sprayAttempt
	lastTry map[string]time.Time
}

var gNATSpray = &natSprayer{active: map[string]*sprayAttempt{}, lastTry: map[string]time.Time{}}

// maybeStartNATSpray runs from the connect signalling once the NAT pairing has
// been judged unpunchable. Only the half this core implements: the peer is the
// symmetric one, we are the port-restricted one probing for its mapping.
func maybeStartNATSpray(overlayIP, candidateList, mine, theirs string) {
	if !natSprayEnabled.Load() || overlayIP == "" {
		return
	}
	if !(mine == natStable && theirs == natSymmetric) {
		return
	}
	// Never toward a peer behind our own NAT: that address is our own router's
	// WAN side, and the ordinary punch already reaches a same-site peer.
	if sameSiteCandidates(candidateList) {
		return
	}
	ep := peerPublicEndpoint(candidateList)
	if ep == nil {
		return
	}
	gNATSpray.start(overlayIP, ep)
}

func sameSiteCandidates(candidateList string) bool {
	selfIP := ""
	if ep := currentPublicEndpoint(); ep != "" {
		if h, _, err := net.SplitHostPort(ep); err == nil {
			selfIP = h
		}
	}
	for _, c := range strings.Split(candidateList, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		h, _, err := net.SplitHostPort(c)
		if err != nil {
			continue
		}
		if selfIP != "" && h == selfIP {
			return true
		}
		if addr, err := net.ResolveUDPAddr("udp", c); err == nil && isAttachedLANAddr(addr) {
			return true
		}
	}
	return false
}

func peerPublicEndpoint(candidateList string) *net.UDPAddr {
	for _, c := range strings.Split(candidateList, ",") {
		c = strings.TrimSpace(c)
		if c == "" || !isPunchableAddr(c) || !isValidPeer(c) {
			continue
		}
		if addr, err := net.ResolveUDPAddr("udp", c); err == nil && addr.IP != nil && addr.IP.To4() != nil {
			return addr
		}
	}
	return nil
}

func (s *natSprayer) start(overlayIP string, ep *net.UDPAddr) {
	s.mu.Lock()
	if _, busy := s.active[overlayIP]; busy {
		s.mu.Unlock()
		return
	}
	if t, ok := s.lastTry[overlayIP]; ok && time.Since(t) < natSprayCooldown {
		s.mu.Unlock()
		return
	}
	if len(s.active) >= natSprayMaxPeers {
		s.mu.Unlock()
		return
	}
	a := &sprayAttempt{overlayIP: overlayIP, peerIP: ep.IP.String(), stop: make(chan struct{})}
	s.active[overlayIP] = a
	s.lastTry[overlayIP] = time.Now()
	s.mu.Unlock()
	go a.run(ep)
}

func (s *natSprayer) finish(a *sprayAttempt) {
	if a.done.Swap(true) {
		return
	}
	close(a.stop)
	s.mu.Lock()
	if s.active[a.overlayIP] == a {
		delete(s.active, a.overlayIP)
	}
	s.mu.Unlock()
}

// found: a sprayed probe was answered, so raddr is a live mapping on the peer.
func (s *natSprayer) found(raddr *net.UDPAddr) {
	ep := raddr.String()
	s.mu.Lock()
	var a *sprayAttempt
	for _, cand := range s.active {
		if cand.peerIP == raddr.IP.String() {
			a = cand
			break
		}
	}
	s.mu.Unlock()
	if a == nil {
		return
	}
	log.Printf("[nat-spray] %s answered at %s — sprayed punch found its mapping, handshaking directly",
		a.overlayIP, ep)
	s.finish(a)
	addKnownPeer(ep)
	go connectToPeer(ep, gKP, gPSK)
}

func directSessionTo(peerIP string) bool {
	if GlobalSessions == nil {
		return false
	}
	for _, a := range GlobalSessions.EstablishedAddrs() {
		if a != nil && a.IP.String() == peerIP {
			return true
		}
	}
	return false
}

func (a *sprayAttempt) run(ep *net.UDPAddr) {
	defer gNATSpray.finish(a)
	conn := GlobalConn
	if conn == nil {
		return
	}
	log.Printf("[nat-spray] %s: %s allocates a fresh port per destination, so its advertised port cannot be punched — "+
		"probing %d ports per round for the mapping it opened toward us", a.overlayIP, ep.IP, natSprayPorts)
	probe := buildSprayFrame(gPSK, sprayProbe, sprayNonce())
	for round := 0; round < natSprayRounds; round++ {
		if directSessionTo(a.peerIP) {
			return
		}
		sent := 0
		for i, port := range sprayPorts(natSprayPorts) {
			select {
			case <-a.stop:
				return
			default:
			}
			// Paced: a thousand datagrams at once is a thousand new flows
			// arriving at the far NAT inside a millisecond.
			if i > 0 && i%64 == 0 {
				time.Sleep(20 * time.Millisecond)
			}
			if port == ep.Port {
				continue
			}
			if _, err := conn.WriteToUDP(probe, &net.UDPAddr{IP: ep.IP, Port: port}); err == nil {
				sent++
			}
		}
		log.Printf("[nat-spray] %s: round %d/%d — %d probes sent", a.overlayIP, round+1, natSprayRounds, sent)
		select {
		case <-a.stop:
			return
		case <-time.After(natSprayGap):
		}
		if directSessionTo(a.peerIP) {
			log.Printf("[nat-spray] %s: direct session up after round %d — stopping", a.overlayIP, round+1)
			return
		}
	}
	log.Printf("[nat-spray] %s: no mapping found in %d rounds — staying on the relay, will retry after %s",
		a.overlayIP, natSprayRounds, natSprayCooldown)
}

func sprayPorts(n int) []int {
	span := natSprayPortHi - natSprayPortLo + 1
	if n > span {
		n = span
	}
	seen := make(map[int]bool, n)
	out := make([]int, 0, n)
	for len(out) < n {
		b, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
		if err != nil {
			return out
		}
		p := natSprayPortLo + int(b.Int64())
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func sprayNonce() []byte {
	n := make([]byte, 8)
	if _, err := rand.Read(n); err != nil {
		binary.BigEndian.PutUint64(n, uint64(time.Now().UnixNano()))
	}
	return n
}
