package main

// natspray.go — punching the pairing relaypolicy.go calls unpunchable.
//
// THE CASE
//
// relaypolicy.go refuses the symmetric/port-restricted pairing outright and
// goes straight to relay, on the reasoning that neither side can address the
// other's current mapping. That reasoning is right about ADDRESSING and wrong
// about IMPOSSIBILITY: what a symmetric NAT denies is prediction, not
// existence. The mapping is there, it just has a port nobody guessed.
//
// The case that forced this file: a Kubernetes pod and a phone. The pod is
// behind kube-proxy's masquerade, which is installed with --random-fully, so
// its external port is drawn at random per destination — its own classifier
// gives up on prediction (natMapping.stride = 0, "symmetric but
// unpredictable"). The phone sits behind a port-restricted home router. Same
// pod, same router, two containers: the one on podman punches fine because
// podman keeps the source port; the pod never punches at all. On cellular it
// works, because carrier NATs accept inbound from a port they never sent to.
// So one network in one house decides whether the product works, and the
// answer "add a port forward" is the answer this project exists to avoid.
//
// THE METHOD — BIRTHDAY PUNCHING
//
// One socket on the symmetric side yields one mapping, and one guess against
// 45,000 ports is hopeless. But the number of mappings is ours to choose:
//
//   - The symmetric side (the one nobody can address) opens natSprayAux
//     ordinary UDP sockets and sends one probe from each to the peer's known,
//     stable endpoint. Its NAT now holds natSprayAux distinct external ports,
//     every one of them willing to accept a datagram from that peer — and only
//     from that peer, which is what keeps this from being a firewall hole.
//
//   - The stable side sprays natSprayPorts probes per round at the symmetric
//     side's public address, from the single socket the peer's mappings are
//     expecting. A probe that lands on any of the open ports is delivered.
//
// THE DETAIL THE WHOLE THING HANGS ON — PROBE TTL
//
// The mapping-opening probes are sent with a small TTL, so they die in the
// middle of the path: past our own NAT, nowhere near the peer's. That is not
// an optimisation, it is the difference between working and not. Measured in
// a netns rig: with ordinary TTL the probes reach the peer's router, which
// records an inbound flow from each of our mapped ports. When the peer then
// sprays those very ports, its NAT finds the reverse tuple already taken and
// renumbers the peer's source port — so the probes arrive from an address our
// mappings never agreed to accept, and the hit rate is exactly zero, no matter
// how many rounds run. Capping the TTL removed that interference and the same
// rig went to three hits out of three aimed ports.
//
// With 48 sockets against a 45,536-port range, a 1,024-port round carries an
// expected hit count just above 1 — so a hit usually lands in the first round
// and is overwhelmingly likely within six. That is the entire trick: it does
// not predict the port, it makes the target big enough to hit by accident, on
// purpose.
//
// WHAT HAPPENS ON A HIT
//
// The probe arrives on one of the auxiliary sockets. That socket's mapping is
// now a working, bidirectional path — but it belongs to THAT socket, not to
// the main one, so every later frame for that peer has to leave through it or
// the peer's restricted NAT drops it as coming from an address it never sent
// to. punchPathFor registers it, overlayWriteTo consults that registry, and
// because every handshake and data frame in this client already funnels
// through overlayWriteTo, the session forms and runs over the auxiliary
// socket with nothing else in the client needing to know.
//
// SAFETY AND MANNERS
//
//   - Probes are authenticated with the network PSK, so only a member can
//     make this node answer, and a reply is exactly as long as the probe it
//     answers: no amplification, in either direction.
//   - Spraying only ever starts from the connect signalling of a peer that is
//     already in our network and only toward the address that peer itself
//     advertised. It is not a scanner; it cannot be pointed at a third party.
//   - Probes never go toward a peer at our own site (sameSiteCandidates): that
//     address is our own router's WAN side, and hairpinning hundreds of flows
//     through a home gateway disturbs everything else behind it.
//   - The port range starts above the well-known ports, and a round is paced
//     rather than emitted as one burst, so a stray probe cannot land on a
//     service and a round cannot spike the far NAT's connection table.
//   - Bounded everywhere: sockets, ports per round, rounds, concurrent peers,
//     a cooldown between attempts, and a janitor that closes idle sockets.
//   - It runs only for the pairing that is otherwise relayed forever, and the
//     relay is never taken away while it tries. The worst case is the status
//     quo plus a few hundred kilobytes.

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
	// natSprayLetter is the control-frame letter for a spray probe. Frames are
	// "OVLYCTL1" + 'y' + kind + nonce(8) + mac(8): 26 bytes, request and reply
	// alike. Older builds hit handleControl's default case and ignore it, so a
	// mixed fleet degrades to today's behaviour instead of breaking.
	natSprayLetter = 'y'
	sprayProbe     = byte(1)
	sprayReply     = byte(2)
	sprayFrameLen  = 1 + 1 + 8 + 8 // letter, kind, nonce, mac

	// natSprayAux is how many mappings the unaddressable side opens. Each is
	// one UDP socket and one 26-byte probe per round; 48 of them put the
	// expected hits per round just above one (48*1024/45536 ≈ 1.08).
	natSprayAux = 48

	// natSprayPorts is how many ports the other side tries per round, drawn
	// without repetition from natSprayPortLo..natSprayPortHi.
	natSprayPorts  = 1024
	natSprayPortLo = 1024
	natSprayPortHi = 65535

	// natSprayRounds and natSprayGap bound one attempt to about twelve
	// seconds — inside relayEscalateAfter, so the relay still takes over on
	// schedule if this fails.
	natSprayRounds = 6
	natSprayGap    = 2 * time.Second

	// natSprayCooldown keeps a failed attempt from repeating in a loop. The
	// next connect signalling after this is allowed to try again.
	natSprayCooldown = 3 * time.Minute

	// natSprayKeepalive refreshes the auxiliary mappings while an attempt is
	// running. Conntrack forgets an unanswered UDP flow in about 30s.
	natSprayKeepalive = 10 * time.Second

	// natSprayIdle closes an auxiliary socket that carried nothing for this
	// long, so a peer that leaves does not cost a socket forever.
	natSprayIdle = 3 * time.Minute

	// natSprayStale drops a path whose peer has no established session: the
	// socket is then carrying nothing and its mapping is likely dead.
	natSprayStale = 60 * time.Second

	// natSprayMaxPeers bounds concurrent attempts, and natSprayMaxSockets
	// bounds the total across them: a node with many symmetric peers must not
	// turn "one attempt per peer" into hundreds of open sockets.
	natSprayMaxPeers   = 2
	natSprayMaxSockets = 96

	// natSprayReplyPerSec bounds how many probes this node will answer, so a
	// member cannot turn the probe responder into a packet engine.
	natSprayReplyPerSec = 400

	// natSprayTTLBase is the first TTL tried for mapping-opening probes, and
	// the ladder climbs one hop per refresh to natSprayTTLMax.
	//
	// It starts LOW on purpose. Too short only costs an attempt: the probe
	// dies before our own NAT, no mapping is created, nothing can hit, and the
	// next refresh tries one hop further. Too long is the expensive mistake —
	// the probe reaches the peer's NAT and poisons the port the peer is about
	// to spray from. So the ladder approaches from the safe side: 2 clears a
	// single masquerade, 3 clears a pod's node plus its router, 4 covers a
	// CGNAT stack, and even 4 expires far inside the ISP on any real path.
	natSprayTTLBase = 2
	natSprayTTLMax  = 4

	// natSprayPathTTL is the ordinary TTL restored on a socket the moment it
	// stops probing and starts carrying a session.
	natSprayPathTTL = 64
)

// natSprayEnabled is OFF unless a node opts in (nat_spray: true /
// NAT_SPRAY=1).
//
// It shipped on-by-default and the first fleet to take it had a bad night. The
// relay path it replaces WORKS — it is slower, not broken — so this is a
// latency optimisation that may not default to on until it has soaked. A
// traversal trick that fires unattended on every node, opens sockets and emits
// port probes has to earn its default, and it has not yet.
var natSprayEnabled atomic.Bool

func init() { natSprayEnabled.Store(false) }

// ------------------------------------------------------------------ paths

// punchPath is an auxiliary socket that won the race for one peer. Traffic for
// that peer must leave through it: its mapping is the one the peer's NAT is
// holding open.
type punchPath struct {
	conn *net.UDPConn
	last atomic.Int64 // unix seconds, last traffic either way
}

var (
	punchPathMu sync.Mutex
	punchPaths  = map[string]*punchPath{} // peer "ip:port" -> socket
)

// punchPathFor returns the auxiliary socket to use for addr, or nil for the
// ordinary main-socket path. Called on every send, so it stays a map lookup.
func punchPathFor(addr *net.UDPAddr) *net.UDPConn {
	if addr == nil {
		return nil
	}
	punchPathMu.Lock()
	p := punchPaths[addr.String()]
	punchPathMu.Unlock()
	if p == nil {
		return nil
	}
	p.last.Store(time.Now().Unix())
	return p.conn
}

func registerPunchPath(addr *net.UDPAddr, conn *net.UDPConn) {
	p := &punchPath{conn: conn}
	p.last.Store(time.Now().Unix())
	punchPathMu.Lock()
	punchPaths[addr.String()] = p
	punchPathMu.Unlock()
}

func dropPunchPath(addr string) {
	punchPathMu.Lock()
	delete(punchPaths, addr)
	punchPathMu.Unlock()
}

// punchPathSnapshot exposes the winning paths to the status API: "this peer is
// direct because a sprayed punch found its mapping" is worth being able to see.
func punchPathSnapshot() []string {
	punchPathMu.Lock()
	defer punchPathMu.Unlock()
	out := make([]string, 0, len(punchPaths))
	for a := range punchPaths {
		out = append(out, a)
	}
	return out
}

// ------------------------------------------------------------------ frames

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

// parseSprayFrame validates a frame body (everything after ctlMagic) and
// returns its kind and nonce. A bad MAC is indistinguishable from noise and
// is dropped without a reply — that is what keeps a stranger's packet from
// getting an answer out of this node.
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

var sprayReplyBudget = newPxRate(natSprayReplyPerSec, natSprayReplyPerSec)

// isNATSprayDatagram recognises a spray frame on the wire.
//
// These frames are PLAINTEXT datagrams, not session payloads: their whole job
// is to be understood by a node that has no session with the sender yet. The
// first version routed them through handleControl, which only ever sees
// DECRYPTED session payloads — so a probe landing on a peer's main socket was
// dropped without an answer and half the protocol was dead on arrival. They
// are demuxed with the other raw frame types instead, and the PSK-keyed MAC is
// what makes them safe to parse from an unknown source.
func isNATSprayDatagram(pkt []byte) bool {
	return len(pkt) == len(ctlMagic)+sprayFrameLen &&
		string(pkt[:len(ctlMagic)]) == string(ctlMagic) &&
		pkt[len(ctlMagic)] == natSprayLetter
}

// handleNATSprayDatagram strips the magic and processes the frame. via is the
// socket it arrived on.
func handleNATSprayDatagram(pkt []byte, raddr *net.UDPAddr, via *net.UDPConn) {
	if !isNATSprayDatagram(pkt) {
		return
	}
	handleNATSprayFrame(pkt[len(ctlMagic):], raddr, via)
}

// handleNATSprayFrame processes a probe or reply. via is the socket it arrived
// on: the main one for a reply to our own spray, an auxiliary one for a probe
// that just found a mapping.
func handleNATSprayFrame(body []byte, raddr *net.UDPAddr, via *net.UDPConn) {
	kind, nonce, ok := parseSprayFrame(body, gPSK)
	if !ok || raddr == nil {
		return
	}
	switch kind {
	case sprayProbe:
		if !sprayReplyBudget.allow() {
			return
		}
		if via != nil && via != GlobalConn {
			// RESTORE THE TTL FIRST. This socket has been sending probes that
			// were deliberately too short-lived to reach the peer; the moment
			// it has a peer to talk to, everything it sends — starting with
			// the reply on the next line — has to survive the whole path. The
			// first version of this promoted the socket while leaving its TTL
			// at 2, and the handshake died in the middle of the network with
			// "no handshake reply", one hop past a punch that had worked.
			_ = setProbeTTL(via, natSprayPathTTL)
		}
		// Answer on the socket it came in on, so the reply leaves through the
		// mapping the peer just found. Same length as the probe.
		if via != nil {
			_, _ = via.WriteToUDP(buildSprayFrame(gPSK, sprayReply, nonce), raddr)
		}
		if via != nil && via != GlobalConn {
			gNATSpray.won(raddr, via)
		}
	case sprayReply:
		// Our spray landed. raddr is the peer's live mapping — a real endpoint,
		// not a guess — so hand it to the ordinary punch path.
		gNATSpray.found(raddr)
	}
}

// ------------------------------------------------------------------ manager

type sprayAttempt struct {
	overlayIP string
	peerIP    string
	started   time.Time
	socks     []*net.UDPConn // auxiliary sockets (symmetric side only)
	stop      chan struct{}
	done      atomic.Bool
}

type natSprayer struct {
	mu       sync.Mutex
	active   map[string]*sprayAttempt // overlay IP -> attempt
	lastTry  map[string]time.Time     // overlay IP -> last attempt start
	auxByAdr map[string]*sprayAttempt // peer "ip:port" -> attempt that won
}

var gNATSpray = &natSprayer{
	active:   map[string]*sprayAttempt{},
	lastTry:  map[string]time.Time{},
	auxByAdr: map[string]*sprayAttempt{},
}

// auxSockets is the live count of auxiliary sockets across all attempts.
var auxSockets atomic.Int64

// maybeStartNATSpray is called from the connect-signalling handler when the
// NAT pairing has been judged unpunchable. mine and theirs are the two NAT
// classes; candidateList is what the peer advertised.
//
// Only the symmetric/stable pairing is attempted. Two symmetric NATs are
// genuinely out of reach: neither side knows an address on the other that its
// own mappings could be aimed at, so there is nothing to spray toward.
func maybeStartNATSpray(overlayIP, candidateList, mine, theirs string) {
	if !natSprayEnabled.Load() || overlayIP == "" {
		return
	}
	var aux bool
	switch {
	case mine == natSymmetric && theirs == natStable:
		aux = true // we are the one nobody can address
	case mine == natStable && theirs == natSymmetric:
		aux = false // they are; we spray at them
	default:
		return
	}
	// NEVER toward a peer at our own site. If any candidate carries our own
	// public address we are behind the SAME NAT, and the only address this
	// would aim at is our own router's WAN side: probes hairpin back into the
	// house, the router carries hundreds of pointless flows, and on a consumer
	// gateway that is a good way to disturb every other device behind it. A
	// peer we share a NAT with is also reachable on the LAN, which the ordinary
	// punch already handles far better than any of this.
	if sameSiteCandidates(candidateList) {
		return
	}
	ep := peerPublicEndpoint(candidateList)
	if ep == nil {
		return
	}
	gNATSpray.start(overlayIP, ep, aux)
}

// peerPublicEndpoint picks the peer's public, routable candidate — the address
// its NAT presents to the world, which is the only one either half of this
// technique can aim at.
// sameSiteCandidates reports whether the peer advertises our own public
// address (we are behind one NAT together) or an address on a subnet this host
// is attached to.
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

func (s *natSprayer) start(overlayIP string, ep *net.UDPAddr, aux bool) {
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
	a := &sprayAttempt{overlayIP: overlayIP, peerIP: ep.IP.String(), started: time.Now(), stop: make(chan struct{})}
	s.active[overlayIP] = a
	s.lastTry[overlayIP] = time.Now()
	s.mu.Unlock()

	if aux {
		go a.runAux(ep)
	} else {
		go a.runSpray(ep)
	}
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

// found is called when a sprayed probe was answered: raddr is a live mapping
// on the peer, so the normal punch path can take it from here.
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

// won is called when a probe arrived on one of OUR auxiliary sockets: that
// socket's mapping is the path, so it is registered before the handshake.
func (s *natSprayer) won(raddr *net.UDPAddr, via *net.UDPConn) {
	ep := raddr.String()
	s.mu.Lock()
	if _, ok := s.auxByAdr[ep]; ok {
		s.mu.Unlock()
		return // already promoted
	}
	var a *sprayAttempt
	for _, cand := range s.active {
		if cand.peerIP == raddr.IP.String() {
			a = cand
			break
		}
	}
	if a != nil {
		s.auxByAdr[ep] = a
	}
	s.mu.Unlock()

	registerPunchPath(raddr, via)
	log.Printf("[nat-spray] %s found one of our mappings — promoting that socket to the path for this peer", ep)
	if a != nil {
		// Stop probing, but keep the sockets: the winning one carries the
		// session now, and closing the set would close it.
		a.done.Store(true)
		s.mu.Lock()
		if s.active[a.overlayIP] == a {
			delete(s.active, a.overlayIP)
		}
		s.mu.Unlock()
	}
	addKnownPeer(ep)
	go connectToPeer(ep, gKP, gPSK)
}

// directSessionTo reports whether an established session already exists with
// any endpoint at this peer's public address. Both halves poll it: the side
// that wins the race learns of success through the handshake rather than
// through its own probe, and neither should keep spraying afterwards.
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

// ------------------------------------------------------------------ the two halves

// runAux opens the mappings. Each socket sends one probe per round to the
// peer's stable endpoint, which is what makes its NAT hold the port open for
// exactly that peer.
func (a *sprayAttempt) runAux(ep *net.UDPAddr) {
	defer gNATSpray.finish(a)
	socks := make([]*net.UDPConn, 0, natSprayAux)
	for i := 0; i < natSprayAux; i++ {
		if auxSockets.Load() >= natSprayMaxSockets {
			break
		}
		c, err := net.ListenUDP("udp4", &net.UDPAddr{})
		if err != nil {
			break
		}
		auxSockets.Add(1)
		socks = append(socks, c)
		go a.readAux(c)
	}
	if len(socks) == 0 {
		return
	}
	a.socks = socks
	log.Printf("[nat-spray] %s: opening %d mappings toward %s so its probes have something to hit",
		a.overlayIP, len(socks), ep)
	probe := buildSprayFrame(gPSK, sprayProbe, sprayNonce())
	tick := time.NewTicker(natSprayKeepalive)
	defer tick.Stop()
	deadline := time.After(natSprayRounds * natSprayGap * 2)
	ttl := natSprayTTLBase
	for {
		// TTL steps up each cycle: too short and the probe never clears our
		// own NAT (no mapping, nothing to hit), too long and it reaches the
		// peer's NAT and spoils the peer's source port (see the file header).
		for _, c := range socks {
			_ = setProbeTTL(c, ttl)
		}
		sent, failed := 0, 0
		for _, c := range socks {
			if _, err := c.WriteToUDP(probe, ep); err != nil {
				failed++
				continue
			}
			sent++
		}
		log.Printf("[nat-spray] %s: refreshed %d mappings toward %s at ttl %d (%d failed)",
			a.overlayIP, sent, ep, ttl, failed)
		if ttl < natSprayTTLMax {
			ttl++
		}
		select {
		case <-a.stop:
			a.closeUnusedAux()
			return
		case <-deadline:
			a.closeUnusedAux()
			return
		case <-tick.C:
		}
		if directSessionTo(a.peerIP) {
			// Won — by our probe or by the peer's, it does not matter which.
			// The winning socket stays open (it is the path now); the rest go.
			a.closeUnusedAux()
			return
		}
	}
}

// readAux serves one auxiliary socket. Before a hit it sees spray probes;
// after one it carries an ordinary session, so everything it reads goes to the
// same dispatcher the main socket uses.
func (a *sprayAttempt) readAux(c *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, raddr, err := c.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if isNATSprayDatagram(buf[:n]) {
			handleNATSprayDatagram(append([]byte(nil), buf[:n]...), raddr, c)
			continue
		}
		// Session traffic on the promoted socket. Copy: the dispatcher may
		// keep the slice past this iteration.
		pkt := append([]byte(nil), buf[:n]...)
		dispatchUDPDatagram(pkt, raddr)
	}
}

// closeUnusedAux closes every auxiliary socket that is not carrying a peer.
func (a *sprayAttempt) closeUnusedAux() {
	punchPathMu.Lock()
	keep := map[*net.UDPConn]bool{}
	for _, p := range punchPaths {
		keep[p.conn] = true
	}
	punchPathMu.Unlock()
	for _, c := range a.socks {
		if !keep[c] {
			_ = c.Close()
			auxSockets.Add(-1)
		}
	}
}

// runSpray is the other half: probe ports at the peer's public address until
// one of them is a mapping its NAT is holding open for us.
func (a *sprayAttempt) runSpray(ep *net.UDPAddr) {
	defer gNATSpray.finish(a)
	conn := GlobalConn
	if conn == nil {
		return
	}
	log.Printf("[nat-spray] %s: %s allocates a fresh port per destination, so its advertised port cannot be punched — "+
		"probing %d ports per round for the mapping it opened toward us",
		a.overlayIP, ep.IP, natSprayPorts)
	probe := buildSprayFrame(gPSK, sprayProbe, sprayNonce())
	for round := 0; round < natSprayRounds; round++ {
		if directSessionTo(a.peerIP) {
			return
		}
		sent, failed := 0, 0
		for i, port := range sprayPorts(natSprayPorts) {
			select {
			case <-a.stop:
				return
			default:
			}
			// Paced. A thousand datagrams emitted back-to-back is a thousand
			// new flows arriving at the far NAT inside a millisecond, which is
			// how a consumer router's connection table gets pushed over — and
			// that router is carrying everything else in the house.
			if i > 0 && i%64 == 0 {
				time.Sleep(20 * time.Millisecond)
			}
			// Never probe the port it already advertised: the ordinary punch
			// has that covered, and it is the one port we know is wrong.
			if port == ep.Port {
				continue
			}
			if _, err := conn.WriteToUDP(probe, &net.UDPAddr{IP: ep.IP, Port: port}); err != nil {
				failed++
				continue
			}
			sent++
		}
		log.Printf("[nat-spray] %s: round %d/%d — %d probes sent, %d failed",
			a.overlayIP, round+1, natSprayRounds, sent, failed)
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

// sprayPorts draws n distinct ports from the range. Random rather than
// sequential so two rounds cover different ground and a NAT's allocator is
// never walked in step.
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

// ------------------------------------------------------------------ janitor

// startNATSprayJanitor closes promoted sockets whose peer has gone quiet.
func startNATSprayJanitor() {
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			cutoff := time.Now().Add(-natSprayIdle).Unix()
			stale := time.Now().Add(-natSprayStale).Unix()
			live := map[string]bool{}
			if GlobalSessions != nil {
				for _, a := range GlobalSessions.EstablishedAddrs() {
					if a != nil {
						live[a.String()] = true
					}
				}
			}
			punchPathMu.Lock()
			for addr, p := range punchPaths {
				// Idle, or the session that justified it is gone. The second
				// case matters: a registered path outlives its session and
				// every later frame for that peer would leave through a socket
				// whose mapping the peer's NAT has long since forgotten.
				if p.last.Load() < cutoff || (!live[addr] && p.last.Load() < stale) {
					_ = p.conn.Close()
					auxSockets.Add(-1)
					delete(punchPaths, addr)
					log.Printf("[nat-spray] %s — closed its punched socket (idle or no session)", addr)
				}
			}
			punchPathMu.Unlock()
		}
	}()
}
