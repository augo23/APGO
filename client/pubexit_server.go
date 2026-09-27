package main

// pubexit_server.go — BEING a public exit node (desktop and server builds;
// phones never serve). Protocol and isolation rules: pubexit_proto.go.
//
// A public exit is the most exposed thing a node can do: strangers' internet
// traffic leaves through the operator's connection and IP address. So it is
//
//   - OFF unless explicitly enabled, and only allowed on a node that has
//     already opted into public service (DHT on AND public relay on);
//   - metered by its own bandwidth budget (separate from the relay and the
//     internal exit), plus a per-client rate and a per-client new-flow rate;
//   - limited in clients, sessions per source address and handshake rate;
//   - restricted to the PUBLIC internet: every packet is checked before it is
//     written to the OS, and the OS is additionally told (iptables / pf) to
//     drop anything from the client pool that is not bound for the internet,
//     and anything addressed to this host;
//   - private: it logs counts, never destinations.

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
)

const (
	pxDefaultMaxClients   = 16
	pxDefaultMaxPerSource = 2
	pxDefaultClientBps    = 10 * 1000 * 1000 / 8 // 10 Mbit/s per client
	pxMaxPending          = 256
	pxHellosPerSec        = 20
	pxNewFlowsPerSec      = 20  // per client
	pxNewFlowsBurst       = 200 // per client
	pxMaxFlows            = 4096
	pxFlowIdle            = 2 * time.Minute
)

// pxDefaultBlockedPorts: outbound SMTP is blocked by default, as nearly every
// ISP and VPN provider does — an open exit is otherwise a spam relay that gets
// the operator's address blocklisted. Configurable (public_exit_block_ports).
var pxDefaultBlockedPorts = []int{25}

// pxPoolCandidates are private, non-internet ranges used for client
// addresses. The first one that overlaps nothing on this host is used.
var pxPoolCandidates = []string{"198.18.0.0/16", "198.19.0.0/16", "100.127.0.0/16"}

type pxFlowKey struct {
	proto byte
	dst   [4]byte
	port  uint16
}

type pxSrvSession struct {
	ch       *pxChannel
	addr     atomic.Pointer[net.UDPAddr]
	src      string // source IP (for the per-source cap)
	poolIP   [4]byte
	created  time.Time
	lastSeen atomic.Int64 // unix nano
	up, down *tokenBucket
	newFlows *pxRate

	flowMu sync.Mutex
	flows  map[pxFlowKey]time.Time

	bytesUp, bytesDown atomic.Uint64
}

type pxPending struct {
	hs      *noise.HandshakeState
	pqss    []byte
	addr    *net.UDPAddr
	created time.Time
}

type pxServer struct {
	enabled atomic.Bool
	conn    *net.UDPConn
	static  noise.DHKey // loaded on first enable (nodes that never serve create no key)
	keyPath string
	limits  *bandwidthLimiter

	mu        sync.Mutex
	pending   map[uint32]*pxPending
	sessions  map[uint32]*pxSrvSession
	byPool    map[[4]byte]*pxSrvSession
	perSource map[string]int

	pool       *net.IPNet
	poolBase   uint32
	poolSize   uint32
	natReady   bool
	natErr     string
	maxClients int
	maxPerSrc  int
	clientBps  int64
	blocked    map[uint16]bool
	hellos     *pxRate

	selfMu   sync.Mutex
	selfIPs  map[[4]byte]bool
	selfSeen time.Time

	advertising atomic.Bool

	statSessions  atomic.Uint64
	statDenied    atomic.Uint64
	statFiltered  atomic.Uint64
	statThrottled atomic.Uint64
	statBytes     atomic.Uint64
}

var gPubExit *pxServer

// pxManualNAT: the operator confirmed the firewall/NAT for the public exit is
// set up by hand (pfSense/FreeBSD only; see pubexit_nat_freebsd.go).
var pxManualNAT atomic.Bool

// publicExitStatePath keeps the public-exit ledger beside the relay one.
func publicExitStatePath() string {
	if p := os.Getenv("PUBLIC_EXIT_STATE_FILE"); p != "" {
		return p
	}
	if rp := relayStatePath(); rp != "" {
		return filepath.Join(filepath.Dir(rp), "public-exit-bandwidth.json")
	}
	return ""
}

// pxLoadStatic loads (or creates) this node's public-exit identity. It is a
// DIFFERENT key from the overlay node key, so strangers who use the exit
// learn nothing that identifies this node inside its own network.
func pxLoadStatic(nodeKeyPath string) noise.DHKey {
	path := ""
	if nodeKeyPath != "" {
		path = filepath.Join(filepath.Dir(nodeKeyPath), "public-exit.key")
	}
	if path != "" {
		if kp, err := loadOrCreateKey(path); err == nil {
			return noise.DHKey{Private: append([]byte(nil), kp.priv[:]...), Public: append([]byte(nil), kp.pub[:]...)}
		}
	}
	k, err := pxNewStatic()
	if err != nil {
		log.Printf("[public-exit] cannot create an identity key: %v", err)
	}
	return k
}

// startPublicExit creates the server in a DISABLED state.
func startPublicExit(conn *net.UDPConn, cfg *ClientConfig) *pxServer {
	s := &pxServer{
		conn:       conn,
		keyPath:    cfg.NodePrivateKey,
		pending:    map[uint32]*pxPending{},
		sessions:   map[uint32]*pxSrvSession{},
		byPool:     map[[4]byte]*pxSrvSession{},
		perSource:  map[string]int{},
		maxClients: pxDefaultMaxClients,
		maxPerSrc:  pxDefaultMaxPerSource,
		clientBps:  pxDefaultClientBps,
		hellos:     newPxRate(pxHellosPerSec, pxHellosPerSec*2),
	}
	days := cfg.PublicExitQuotaDays
	if days <= 0 {
		days = 30
	}
	s.limits = newBandwidthLimiter(parseRate(cfg.PublicExitUpLimit), parseRate(cfg.PublicExitDownLimit),
		parseRate(cfg.PublicExitQuota), days, publicExitStatePath())
	if cfg.PublicExitMaxClients > 0 {
		s.maxClients = cfg.PublicExitMaxClients
	}
	if v := parseRate(cfg.PublicExitPerClientLimit); v > 0 {
		s.clientBps = v
	}
	s.setBlockedPorts(cfg.PublicExitBlockPorts)
	gPubExit = s
	go s.janitor()
	go s.advertiseLoop()
	return s
}

func (s *pxServer) setBlockedPorts(ports []int) {
	if ports == nil {
		ports = pxDefaultBlockedPorts
	}
	m := map[uint16]bool{}
	for _, p := range ports {
		if p > 0 && p < 65536 {
			m[uint16(p)] = true
		}
	}
	s.mu.Lock()
	s.blocked = m
	s.mu.Unlock()
}

// publicExitPrereqs explains why this node may not be a public exit, or "".
func publicExitPrereqs() string {
	var missing []string
	if gDHT == nil || !gDHT.enabled.Load() {
		missing = append(missing, "the DHT")
	}
	if gPublicRelay == nil || !gPublicRelay.enabled.Load() {
		missing = append(missing, "public relay")
	}
	if len(missing) == 0 {
		return ""
	}
	return "a public exit node must also have " + strings.Join(missing, " and ") + " turned on"
}

// SetEnabled switches public-exit service. Enabling checks the prerequisites
// and sets up the address pool and OS NAT first; it fails (and stays off)
// rather than advertise a service it cannot safely provide.
func (s *pxServer) SetEnabled(on bool) error {
	if !on {
		if s.enabled.Swap(false) {
			n := s.closeAll()
			log.Printf("[public-exit] public exit node OFF — closed %d client session(s)", n)
		}
		return nil
	}
	if s.enabled.Load() {
		return nil
	}
	if why := publicExitPrereqs(); why != "" {
		return fmt.Errorf("%s", why)
	}
	s.mu.Lock()
	if len(s.static.Private) == 0 {
		s.static = pxLoadStatic(s.keyPath)
		if len(s.static.Private) == 0 {
			s.mu.Unlock()
			return fmt.Errorf("no public-exit identity key")
		}
	}
	if s.pool == nil {
		pool, err := pxChoosePool()
		if err != nil {
			s.mu.Unlock()
			return err
		}
		s.pool = pool
		s.poolBase = binary.BigEndian.Uint32(pool.IP.To4())
		ones, bits := pool.Mask.Size()
		s.poolSize = 1<<uint(bits-ones) - 2
	}
	pool := s.pool
	ready := s.natReady
	s.mu.Unlock()
	if !ready {
		if err := setupPublicExitNAT(pool); err != nil {
			s.mu.Lock()
			s.natErr = err.Error()
			s.mu.Unlock()
			return fmt.Errorf("could not set up internet sharing: %v", err)
		}
		s.mu.Lock()
		s.natReady, s.natErr = true, ""
		s.mu.Unlock()
	}
	s.enabled.Store(true)
	st := s.limits.Status()
	log.Printf("[public-exit] public exit node ON — sharing this connection with any APGO user "+
		"(internet only; clients in %s; up=%s down=%s quota=%s; max %d clients)",
		pool, formatRate(s.limits.up.Rate()), formatRate(s.limits.down.Rate()), formatRate(st.QuotaBytes), s.maxClients)
	go s.advertise()
	return nil
}

// Configure applies new limits live.
func (s *pxServer) Configure(up, down, quota int64, maxClients int, perClient int64) {
	s.limits.Configure(up, down, quota, 0)
	s.mu.Lock()
	if maxClients > 0 {
		s.maxClients = maxClients
	}
	if perClient > 0 {
		s.clientBps = perClient
	}
	for _, ss := range s.sessions {
		ss.up.SetRate(s.clientBps)
		ss.down.SetRate(s.clientBps)
	}
	s.mu.Unlock()
}

// pxChoosePool picks the first candidate range that no interface on this host
// uses and that does not overlap the overlay.
func pxChoosePool() (*net.IPNet, error) {
	var local []*net.IPNet
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifi := range ifs {
			addrs, _ := ifi.Addrs()
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
					local = append(local, n)
				}
			}
		}
	}
	if overlayNet != nil {
		local = append(local, overlayNet)
	}
	overlaps := func(a, b *net.IPNet) bool { return a.Contains(b.IP) || b.Contains(a.IP) }
next:
	for _, c := range pxPoolCandidates {
		_, pool, _ := net.ParseCIDR(c)
		for _, l := range local {
			if overlaps(pool, l) {
				continue next
			}
		}
		return pool, nil
	}
	return nil, fmt.Errorf("no free address range for public-exit clients (all of %s are in use on this host)",
		strings.Join(pxPoolCandidates, ", "))
}

func (s *pxServer) inPool(ip [4]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pool != nil && s.pool.Contains(net.IP(ip[:]))
}

func (s *pxServer) send(addr *net.UDPAddr, b []byte) {
	if s.conn != nil && addr != nil {
		_, _ = s.conn.WriteToUDP(b, addr)
	}
}

func (s *pxServer) deny(addr *net.UDPAddr, reason byte) {
	s.statDenied.Add(1)
	s.send(addr, []byte{PktPubExit, pxDeny, reason})
}

// handlePubExitPacket is the demux entry for PktPubExit datagrams: server
// messages go to the public exit we run, client messages to the public exit
// we use.
func handlePubExitPacket(data []byte, raddr *net.UDPAddr) {
	if len(data) < 2 {
		return
	}
	switch data[1] {
	case pxHello, pxFinish:
		if s := gPubExit; s != nil {
			s.handleHandshake(data, raddr)
		}
	case pxData:
		sid, ok := pxSessionID(data)
		if !ok {
			return
		}
		if s := gPubExit; s != nil && s.handleData(sid, data, raddr) {
			return
		}
		if c := gPxClient; c != nil {
			c.handleData(sid, data, raddr)
		}
	case pxHelloReply, pxDeny:
		if c := gPxClient; c != nil {
			c.handleHandshake(data, raddr)
		}
	}
}

func (s *pxServer) handleHandshake(data []byte, raddr *net.UDPAddr) {
	if !s.enabled.Load() {
		// Deny only a correctly sized hello: never answer junk.
		if data[1] == pxHello && len(data) == pxHelloSize {
			s.deny(raddr, pxDenyDisabled)
		}
		return
	}
	switch data[1] {
	case pxHello:
		s.onHello(data, raddr)
	case pxFinish:
		s.onFinish(data, raddr)
	}
}

// onHello: [type][sub][ver][len 2][noise msg1 = e + ML-KEM pk][padding]
func (s *pxServer) onHello(data []byte, raddr *net.UDPAddr) {
	if len(data) != pxHelloSize {
		return // wrong size: silently ignored (anti-amplification)
	}
	if data[2] != pxVersion {
		s.deny(raddr, pxDenyVersion)
		return
	}
	if !s.hellos.allow() {
		s.statDenied.Add(1)
		return // no reply when flooded
	}
	if s.limits.QuotaExceeded() {
		s.deny(raddr, pxDenyQuota)
		return
	}
	src := raddr.IP.String()
	s.mu.Lock()
	full := len(s.sessions) >= s.maxClients || len(s.pending) >= pxMaxPending
	perSrc := s.perSource[src] >= s.maxPerSrc
	s.mu.Unlock()
	if full {
		s.deny(raddr, pxDenyFull)
		return
	}
	if perSrc {
		s.deny(raddr, pxDenyRate)
		return
	}
	n := int(binary.BigEndian.Uint16(data[3:5]))
	if n <= 0 || 5+n > len(data) {
		return
	}
	s.mu.Lock()
	static := s.static
	s.mu.Unlock()
	hs, err := noise.NewHandshakeState(pxNoiseConfig(false, static))
	if err != nil {
		return
	}
	payload, _, _, err := hs.ReadMessage(nil, data[5:5+n])
	if err != nil {
		return
	}
	pk, err := pxScheme().UnmarshalBinaryPublicKey(payload)
	if err != nil {
		return
	}
	ct, ss, err := pxScheme().Encapsulate(pk)
	if err != nil {
		return
	}
	msg2, _, _, err := hs.WriteMessage(nil, append([]byte{pxVersion}, ct...))
	if err != nil {
		return
	}
	sid, ok := s.newSessionID()
	if !ok {
		return
	}
	s.mu.Lock()
	s.pending[sid] = &pxPending{hs: hs, pqss: ss, addr: raddr, created: time.Now()}
	s.perSource[src]++
	s.mu.Unlock()

	out := make([]byte, 0, 2+4+2+len(msg2))
	out = append(out, PktPubExit, pxHelloReply)
	out = binary.BigEndian.AppendUint32(out, sid)
	out = binary.BigEndian.AppendUint16(out, uint16(len(msg2)))
	out = append(out, msg2...)
	if len(out) >= pxHelloSize {
		return // never amplify (cannot happen with ML-KEM-768 sizes)
	}
	s.send(raddr, out)
}

func (s *pxServer) newSessionID() (uint32, bool) {
	var b [4]byte
	for i := 0; i < 8; i++ {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, false
		}
		id := binary.BigEndian.Uint32(b[:])
		if id == 0 {
			continue
		}
		s.mu.Lock()
		_, a := s.pending[id]
		_, c := s.sessions[id]
		s.mu.Unlock()
		if !a && !c {
			return id, true
		}
	}
	return 0, false
}

// onFinish: [type][sub][sid 4][len 2][noise msg3]
func (s *pxServer) onFinish(data []byte, raddr *net.UDPAddr) {
	if len(data) < 8 {
		return
	}
	sid := binary.BigEndian.Uint32(data[2:6])
	n := int(binary.BigEndian.Uint16(data[6:8]))
	if n <= 0 || 8+n > len(data) {
		return
	}
	s.mu.Lock()
	if ss, ok := s.sessions[sid]; ok {
		// Retransmitted finish: the assignment was lost. Resend it — but
		// only to the address the session belongs to.
		s.mu.Unlock()
		if a := ss.addr.Load(); a != nil && a.String() == raddr.String() {
			s.send(a, ss.ch.seal(pxInAssign, s.assignBody(ss)))
		}
		return
	}
	p, ok := s.pending[sid]
	if ok {
		delete(s.pending, sid)
	}
	s.mu.Unlock()
	if !ok {
		return
	}
	src := p.addr.IP.String()
	release := func() {
		s.mu.Lock()
		s.decSource(src)
		s.mu.Unlock()
	}
	if p.addr.String() != raddr.String() || time.Since(p.created) > pxHandshakeTTL {
		release()
		return
	}
	_, cs1, cs2, err := p.hs.ReadMessage(nil, data[8:8+n])
	if err != nil || cs1 == nil || cs2 == nil {
		release()
		return
	}
	send, recv, err := pxDeriveKeys(false, cs1, cs2, p.hs.ChannelBinding(), p.pqss)
	if err != nil {
		release()
		return
	}
	ss := &pxSrvSession{
		ch:       &pxChannel{sid: sid, send: send, recv: recv},
		src:      src,
		created:  time.Now(),
		newFlows: newPxRate(pxNewFlowsPerSec, pxNewFlowsBurst),
		flows:    map[pxFlowKey]time.Time{},
	}
	ss.addr.Store(raddr)
	ss.lastSeen.Store(time.Now().UnixNano())
	s.mu.Lock()
	if len(s.sessions) >= s.maxClients {
		s.decSource(src)
		s.mu.Unlock()
		s.deny(raddr, pxDenyFull)
		return
	}
	ip, ok := s.allocLocked()
	if !ok {
		s.decSource(src)
		s.mu.Unlock()
		s.deny(raddr, pxDenyFull)
		return
	}
	ss.poolIP = ip
	ss.up = newTokenBucket(s.clientBps)
	ss.down = newTokenBucket(s.clientBps)
	s.sessions[sid] = ss
	s.byPool[ip] = ss
	s.mu.Unlock()
	s.statSessions.Add(1)
	s.limits.NoteCircuit()
	s.send(raddr, ss.ch.seal(pxInAssign, s.assignBody(ss)))
}

func (s *pxServer) assignBody(ss *pxSrvSession) []byte {
	b := make([]byte, 10)
	copy(b[:4], ss.poolIP[:])
	binary.BigEndian.PutUint16(b[4:6], pxMTU)
	binary.BigEndian.PutUint32(b[6:10], uint32(pxLease/time.Second))
	return b
}

// decSource: caller holds s.mu.
func (s *pxServer) decSource(src string) {
	if s.perSource[src] <= 1 {
		delete(s.perSource, src)
	} else {
		s.perSource[src]--
	}
}

// allocLocked picks a free pool address (never .0, never the pool's first
// host, which Windows uses as the adapter address). Caller holds s.mu.
func (s *pxServer) allocLocked() ([4]byte, bool) {
	var out [4]byte
	if s.poolSize < 3 {
		return out, false
	}
	var r [4]byte
	_, _ = rand.Read(r[:])
	start := binary.BigEndian.Uint32(r[:]) % (s.poolSize - 1)
	for i := uint32(0); i < s.poolSize-1; i++ {
		host := 2 + (start+i)%(s.poolSize-1)
		binary.BigEndian.PutUint32(out[:], s.poolBase+host)
		if _, used := s.byPool[out]; !used {
			return out, true
		}
	}
	return out, false
}

// handleData processes a sealed datagram for one of OUR sessions. It returns
// false if the datagram is not one of ours — unknown id, or one that does not
// authenticate (a node that also USES a public exit can see the same 32-bit
// id from that exit; the client half then gets its turn).
func (s *pxServer) handleData(sid uint32, data []byte, raddr *net.UDPAddr) bool {
	s.mu.Lock()
	ss, ok := s.sessions[sid]
	s.mu.Unlock()
	if !ok {
		return false
	}
	kind, body, err := ss.ch.open(data)
	if err == errPxRepl {
		return true
	}
	if err != nil {
		return false
	}
	// Authenticated: follow the client if its address changed (NAT rebind).
	if a := ss.addr.Load(); a == nil || a.String() != raddr.String() {
		ss.addr.Store(raddr)
	}
	ss.lastSeen.Store(time.Now().UnixNano())
	switch kind {
	case pxInPacket:
		if s.enabled.Load() {
			s.fromClient(ss, body)
		}
	case pxInPing:
		if len(body) <= 64 {
			s.send(raddr, ss.ch.seal(pxInPong, body))
		}
	case pxInClose:
		s.remove(sid, false)
	}
	return true
}

// pxAllowedDestination is the public exit's outbound policy: the public
// internet only — never private/overlay/reserved space, never this host.
func (s *pxServer) pxAllowedDestination(p pxIPv4) bool {
	// IP OPTIONS ARE REFUSED. A header longer than 20 bytes carries options,
	// and the only ones a client could want here are the ones an exit must
	// never emit on someone else's behalf: loose/strict source routing (which
	// turns this node into a reflector aimed wherever the option says),
	// record-route and timestamp (which leak the path back to the sender).
	// Nothing legitimate on a VPN needs them.
	if p.ihl != 20 {
		return false
	}
	if !pxIsPublicIPv4(p.dst) {
		return false
	}
	if overlayNet != nil && overlayNet.Contains(net.IP(p.dst[:])) {
		return false
	}
	if s.isSelf(p.dst) {
		return false
	}
	switch p.proto {
	case 6, 17:
	case 1:
		// Clients may ping; other ICMP a client could send (redirects,
		// router adverts, errors) has no business leaving through an exit.
		if p.firstFrg && p.icmpType != 8 {
			return false
		}
	default:
		return false
	}
	if p.hasPort {
		s.mu.Lock()
		blocked := s.blocked[p.dport]
		s.mu.Unlock()
		if blocked {
			return false
		}
	}
	return true
}

// isSelf reports whether ip is one of this host's own addresses (every
// interface, plus the public address STUN observed). Cached for a minute.
func (s *pxServer) isSelf(ip [4]byte) bool {
	s.selfMu.Lock()
	defer s.selfMu.Unlock()
	if s.selfIPs == nil || time.Since(s.selfSeen) > time.Minute {
		m := map[[4]byte]bool{}
		if ifs, err := net.Interfaces(); err == nil {
			for _, ifi := range ifs {
				addrs, _ := ifi.Addrs()
				for _, a := range addrs {
					if n, ok := a.(*net.IPNet); ok {
						if v4 := n.IP.To4(); v4 != nil {
							var k [4]byte
							copy(k[:], v4)
							m[k] = true
						}
					}
				}
			}
		}
		if h, _, err := net.SplitHostPort(currentPublicEndpoint()); err == nil {
			if v4 := net.ParseIP(h).To4(); v4 != nil {
				var k [4]byte
				copy(k[:], v4)
				m[k] = true
			}
		}
		s.selfIPs, s.selfSeen = m, time.Now()
	}
	return s.selfIPs[ip]
}

// flowAllowed charges new flows against the client's new-flow rate (scanning
// and connection-flood protection). Caller passes a parsed first fragment.
func (ss *pxSrvSession) flowAllowed(p pxIPv4) bool {
	if !p.hasPort && p.proto != 1 {
		return true
	}
	k := pxFlowKey{proto: p.proto, dst: p.dst, port: p.dport}
	now := time.Now()
	ss.flowMu.Lock()
	defer ss.flowMu.Unlock()
	if _, ok := ss.flows[k]; ok {
		ss.flows[k] = now
		return true
	}
	if len(ss.flows) >= pxMaxFlows {
		for fk, t := range ss.flows {
			if now.Sub(t) > pxFlowIdle {
				delete(ss.flows, fk)
			}
		}
		if len(ss.flows) >= pxMaxFlows {
			return false
		}
	}
	if !ss.newFlows.allow() {
		return false
	}
	ss.flows[k] = now
	return true
}

func (s *pxServer) fromClient(ss *pxSrvSession, pkt []byte) {
	p, ok := pxParse(pkt)
	if !ok || !s.pxAllowedDestination(p) || (p.firstFrg && !ss.flowAllowed(p)) {
		s.statFiltered.Add(1)
		return
	}
	if !ss.up.Allow(len(pkt)) || !s.limits.AllowUp(len(pkt)) {
		s.statThrottled.Add(1)
		return
	}
	// Anti-spoofing: whatever source the client wrote, the packet leaves as
	// the client's assigned pool address.
	buf := append([]byte(nil), pkt...)
	if !pxRewrite(buf, true, ss.poolIP) {
		s.statFiltered.Add(1)
		return
	}
	ss.bytesUp.Add(uint64(len(buf)))
	s.statBytes.Add(uint64(len(buf)))
	if tunIF != nil {
		_, _ = tunIF.Write(buf)
	}
}

// pubExitFromTUN takes return traffic for pool addresses off the TUN read
// path. It returns true when the packet belonged to the public exit (even if
// it was then dropped), so the overlay code never sees it.
func pubExitFromTUN(pkt []byte) bool {
	s := gPubExit
	if s == nil || len(pkt) < 20 || pkt[0]>>4 != 4 {
		return false
	}
	var dst [4]byte
	copy(dst[:], pkt[16:20])
	if !s.inPool(dst) {
		return false
	}
	if !s.enabled.Load() {
		return true
	}
	s.mu.Lock()
	ss := s.byPool[dst]
	s.mu.Unlock()
	if ss == nil {
		return true
	}
	var src [4]byte
	copy(src[:], pkt[12:16])
	if !pxIsPublicIPv4(src) {
		return true // only the internet answers a public-exit client
	}
	if !ss.down.Allow(len(pkt)) || !s.limits.AllowDown(len(pkt)) {
		s.statThrottled.Add(1)
		return true
	}
	ss.bytesDown.Add(uint64(len(pkt)))
	s.statBytes.Add(uint64(len(pkt)))
	if a := ss.addr.Load(); a != nil {
		s.send(a, ss.ch.seal(pxInPacket, pkt))
	}
	return true
}

func (s *pxServer) remove(sid uint32, notify bool) {
	s.mu.Lock()
	ss, ok := s.sessions[sid]
	if ok {
		delete(s.sessions, sid)
		delete(s.byPool, ss.poolIP)
		s.decSource(ss.src)
	}
	s.mu.Unlock()
	if ok && notify {
		if a := ss.addr.Load(); a != nil {
			s.send(a, ss.ch.seal(pxInClose, nil))
		}
	}
}

func (s *pxServer) closeAll() int {
	s.mu.Lock()
	ids := make([]uint32, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	for id, p := range s.pending {
		delete(s.pending, id)
		s.decSource(p.addr.IP.String())
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.remove(id, true)
	}
	return len(ids)
}

func (s *pxServer) janitor() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		var expired []uint32
		s.mu.Lock()
		for id, p := range s.pending {
			if now.Sub(p.created) > pxHandshakeTTL {
				delete(s.pending, id)
				s.decSource(p.addr.IP.String())
			}
		}
		for id, ss := range s.sessions {
			idle := now.Sub(time.Unix(0, ss.lastSeen.Load())) > pxIdle
			if idle || now.Sub(ss.created) > pxLease+10*time.Minute {
				expired = append(expired, id)
			}
		}
		s.mu.Unlock()
		for _, id := range expired {
			s.remove(id, true)
		}
		if s.enabled.Load() {
			// The operator's opt-in to public service is the condition for
			// this one; if they withdraw it, stop.
			if why := publicExitPrereqs(); why != "" {
				_ = s.SetEnabled(false)
				log.Printf("[public-exit] stopped: %s", why)
			} else if s.limits.QuotaExceeded() {
				if n := s.closeAll(); n > 0 {
					log.Printf("[public-exit] bandwidth quota used up — closed %d client session(s)", n)
				}
			}
		}
	}
}

// advertise publishes this exit in the DHT and on trackers.
func (s *pxServer) advertise() {
	if !s.enabled.Load() || s.limits.QuotaExceeded() || s.conn == nil {
		return
	}
	if !s.advertising.CompareAndSwap(false, true) {
		return
	}
	defer s.advertising.Store(false)
	port := s.conn.LocalAddr().(*net.UDPAddr).Port
	if p := myUDPPort; p > 0 {
		port = p
	}
	if gDHT != nil && gDHT.enabled.Load() {
		gDHT.lookupPeers(pxDirectoryKey(), port)
	}
	directoryPeers("public-exit", pxDirectoryKey(), currentTrackers(), port)
}

func (s *pxServer) advertiseLoop() {
	time.Sleep(30 * time.Second)
	for {
		s.advertise()
		time.Sleep(dhtJitter(relayAdvertisePeriod))
	}
}

// --- status / control ---------------------------------------------------------

type pxServerStatus struct {
	Enabled       bool            `json:"enabled"`
	Error         string          `json:"error,omitempty"`
	Prerequisite  string          `json:"prerequisite,omitempty"`
	Clients       int             `json:"clients"`
	MaxClients    int             `json:"max_clients"`
	PerClientBps  int64           `json:"per_client_bps"`
	Pool          string          `json:"pool,omitempty"`
	BlockedPorts  []int           `json:"blocked_ports"`
	SessionsTotal uint64          `json:"sessions_total"`
	Denied        uint64          `json:"denied"`
	Filtered      uint64          `json:"filtered"`
	Throttled     uint64          `json:"throttled"`
	BytesCarried  uint64          `json:"bytes_carried"`
	Bandwidth     bandwidthStatus `json:"bandwidth"`
}

func publicExitStatus() pxServerStatus {
	s := gPubExit
	if s == nil {
		return pxServerStatus{}
	}
	s.mu.Lock()
	st := pxServerStatus{
		Enabled:      s.enabled.Load(),
		Error:        s.natErr,
		Clients:      len(s.sessions),
		MaxClients:   s.maxClients,
		PerClientBps: s.clientBps,
	}
	if s.pool != nil {
		st.Pool = s.pool.String()
	}
	for p := range s.blocked {
		st.BlockedPorts = append(st.BlockedPorts, int(p))
	}
	s.mu.Unlock()
	st.Prerequisite = publicExitPrereqs()
	st.SessionsTotal = s.statSessions.Load()
	st.Denied = s.statDenied.Load()
	st.Filtered = s.statFiltered.Load()
	st.Throttled = s.statThrottled.Load()
	st.BytesCarried = s.statBytes.Load()
	st.Bandwidth = s.limits.Status()
	return st
}

// publicExitRequest is the control-API body for /api/public-exit.
type publicExitRequest struct {
	Enabled      *bool   `json:"enabled"`
	Up           *string `json:"up"`
	Down         *string `json:"down"`
	Quota        *string `json:"quota"`
	MaxClients   *int    `json:"max_clients"`
	PerClient    *string `json:"per_client"`
	BlockedPorts *string `json:"blocked_ports"` // "25,465"
}

func applyPublicExitRequest(req publicExitRequest) error {
	s := gPubExit
	if s == nil {
		return fmt.Errorf("public exit service is not available on this node")
	}
	st := s.limits.Status()
	up, down, quota := s.limits.up.Rate(), s.limits.down.Rate(), st.QuotaBytes
	if req.Up != nil {
		up = parseRate(*req.Up)
	}
	if req.Down != nil {
		down = parseRate(*req.Down)
	}
	if req.Quota != nil {
		quota = parseRate(*req.Quota)
	}
	maxC := 0
	if req.MaxClients != nil {
		maxC = *req.MaxClients
	}
	var per int64
	if req.PerClient != nil {
		per = parseRate(*req.PerClient)
	}
	s.Configure(up, down, quota, maxC, per)
	if req.BlockedPorts != nil {
		var ports []int
		for _, f := range strings.FieldsFunc(*req.BlockedPorts, func(r rune) bool { return r == ',' || r == ' ' }) {
			if p, err := strconv.Atoi(f); err == nil {
				ports = append(ports, p)
			}
		}
		if ports == nil {
			ports = []int{}
		}
		s.setBlockedPorts(ports)
	}
	if req.Enabled != nil {
		return s.SetEnabled(*req.Enabled)
	}
	return nil
}
