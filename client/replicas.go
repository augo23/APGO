package main

// replicas.go — SERVICE REPLICAS: copies of one node's service running on
// other nodes, with every client sending each new connection to the FASTEST
// copy.
//
// WHY
//
// A service people reach by name (NPM behind *.kube.example, resolving to
// 10.22.22.22) is owned by one node, so every client paid the round trip to
// wherever that node ran: a laptop at home reaching a service at home went
// home -> remote site -> home and back again, even with a copy of the same
// service (a read-only NPM) running on a machine next to it.
//
// HOW
//
// The address's OWNER says where copies of its service run: "my tcp/443 is
// also served on tcp/6943 at 10.22.22.7, 10.22.22.11, …" ('I' frame, version
// 2, on every keepalive). It health-checks each copy through the overlay and
// lists only the ones that accept connections. A client opening a NEW
// connection to the owner's address on a listed port picks the fastest of
// {the owner, each listed node}, measured with the same 'e'/'r' pings exit
// selection uses. When a copy wins, the client rewrites the packet's
// destination (address and port) to that node and rewrites the replies back,
// so applications only ever see the owner's address. A connection stays on
// the node it started on.
//
// The copies run on ORDINARY nodes reached at their own addresses — on
// Kubernetes, each machine's own overlay client, with the copy listening on a
// hostPort. Nothing new joins the overlay, no node serves an address it does
// not own, and no packet on the wire claims a source address its sender does
// not own: the rewriting happens on the client, for the client.
//
// SECURITY
//
//   - Only the address's owner (the key ipbinding.go binds to it), admitted,
//     can publish copies for it. It could already proxy that traffic anywhere
//     it liked, so the announce gives it no new power.
//   - A copy is used only over a direct, proven-live session with the key
//     that owns the copy's address (ipBindings.IsNodeAt) — never via a relay
//     or a node merely claiming the address.
//   - A reply is rewritten back only when it matches a connection this client
//     itself sent to that node (protocol, node, node port, our port). Nothing
//     else can appear to come from the owner's address.
//
// Everything else for the owner's address — other ports, ICMP, fragments,
// clients without this build, the iOS core — goes to the owner as before.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	replicaProbeEvery    = 5 * time.Second
	replicaHealthEvery   = 10 * time.Second
	replicaHealthTimeout = 3 * time.Second
	replicaMaxNodes      = 64
	replicaFlowIdleTCP   = 15 * time.Minute
	replicaFlowIdleOther = 2 * time.Minute
	replicaMaxFlows      = 65536
	// A new fastest node takes over new connections only when it is clearly
	// faster: at least replicaSwitchRatio of the current RTT AND
	// replicaSwitchMinMs quicker.
	replicaSwitchRatio = 0.8
	replicaSwitchMinMs = 3.0
	// rttUnknown marks a candidate that has not answered a ping yet.
	rttUnknown = -1.0
	// replicaAnnounceVersion is the first payload byte of an 'I' frame.
	// Version 1 was the retired anycast "I serve this address" announce;
	// builds that know only version 1 ignore this one.
	replicaAnnounceVersion = 2
)

// replicaAnnounceTTL is how long an announce stays valid without being
// repeated: three keepalives, and never under 30 s.
func replicaAnnounceTTL() time.Duration {
	t := 3 * gKeepaliveInterval
	if t < 30*time.Second {
		t = 30 * time.Second
	}
	return t
}

// ---------------------------------------------------------------------------
// Port maps
// ---------------------------------------------------------------------------

const (
	protoTCP byte = 6
	protoUDP byte = 17
)

type portKey struct {
	proto byte
	port  uint16
}

// replicaPorts maps a port on the owner's address to the port the copies
// listen on: tcp/443 -> 6943.
type replicaPorts map[portKey]uint16

func protoName(p byte) string {
	if p == protoUDP {
		return "udp"
	}
	return "tcp"
}

// String is the CANONICAL form, "tcp/80=6980,tcp/443=6943,udp/53=53": TCP
// before UDP, ports ascending.
func (m replicaPorts) String() string {
	keys := make([]portKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].proto != keys[j].proto {
			return keys[i].proto < keys[j].proto
		}
		return keys[i].port < keys[j].port
	})
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s/%d=%d", protoName(k.proto), k.port, m[k]))
	}
	return strings.Join(parts, ",")
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("bad port %q", s)
	}
	return uint16(n), nil
}

// parseReplicaPorts parses "tcp/80=6980,tcp/443=6943". "tcp/443" alone means
// the copies listen on the same port. Whitespace is ignored and protocol
// names are case-insensitive.
func parseReplicaPorts(s string) (replicaPorts, error) {
	out := replicaPorts{}
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		from, to, mapped := strings.Cut(item, "=")
		proto, portStr, ok := strings.Cut(strings.TrimSpace(from), "/")
		if !ok {
			return nil, fmt.Errorf("%q: want proto/port[=port], e.g. tcp/443=6943", item)
		}
		var k portKey
		switch strings.ToLower(strings.TrimSpace(proto)) {
		case "tcp":
			k.proto = protoTCP
		case "udp":
			k.proto = protoUDP
		default:
			return nil, fmt.Errorf("%q: protocol must be tcp or udp", item)
		}
		var err error
		if k.port, err = parsePort(portStr); err != nil {
			return nil, fmt.Errorf("%q: %v", item, err)
		}
		target := k.port
		if mapped {
			if target, err = parsePort(to); err != nil {
				return nil, fmt.Errorf("%q: %v", item, err)
			}
		}
		out[k] = target
	}
	if len(out) == 0 {
		return nil, errors.New("no ports given (use e.g. tcp/80=6980,tcp/443=6943)")
	}
	return out, nil
}

// parseNodeList parses overlay addresses separated by commas or whitespace,
// dropping anything outside the overlay, except, duplicates, and anything
// past replicaMaxNodes. Order is kept.
func parseNodeList(items []string, except string) []string {
	var out []string
	seen := map[string]bool{}
	for _, item := range items {
		for _, f := range strings.FieldsFunc(item, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
			ip := net.ParseIP(f)
			if ip == nil || ip.To4() == nil {
				continue
			}
			s := ip.To4().String()
			if s == except || seen[s] || !inOverlaySubnet(s) {
				continue
			}
			seen[s] = true
			out = append(out, s)
			if len(out) == replicaMaxNodes {
				return out
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Owner side: publish the copies, health-checked
// ---------------------------------------------------------------------------

var (
	ownerMu      sync.Mutex
	ownerPorts   replicaPorts
	ownerNodes   []string
	ownerHealthy = map[string]bool{}

	// replicaDial is the health check (a test hook).
	replicaDial = func(addr string, timeout time.Duration) error {
		c, err := net.DialTimeout("tcp", addr, timeout)
		if err == nil {
			c.Close()
		}
		return err
	}
)

// initReplicas reads replica_ports / replica_nodes (or REPLICA_PORTS /
// REPLICA_NODES, which win) and starts the health checker. Both empty: this
// node publishes nothing.
func initReplicas(cfg *ClientConfig) {
	portSpec := strings.TrimSpace(cfg.ReplicaPorts)
	if env := strings.TrimSpace(os.Getenv("REPLICA_PORTS")); env != "" {
		portSpec = env
	}
	nodeSpec := cfg.ReplicaNodes
	if env := strings.TrimSpace(os.Getenv("REPLICA_NODES")); env != "" {
		nodeSpec = []string{env}
	}
	if portSpec == "" && len(nodeSpec) == 0 {
		return
	}
	ports, err := parseReplicaPorts(portSpec)
	if err != nil {
		log.Printf("[replicas] IGNORING replica settings: replica_ports: %v", err)
		return
	}
	hasTCP := false
	for k := range ports {
		hasTCP = hasTCP || k.proto == protoTCP
	}
	if !hasTCP {
		log.Printf("[replicas] IGNORING replica settings: replica_ports needs at least one tcp port to health-check")
		return
	}
	nodes := parseNodeList(nodeSpec, myOverlayIP())
	if len(nodes) == 0 {
		log.Printf("[replicas] IGNORING replica settings: replica_nodes has no overlay addresses")
		return
	}
	ownerMu.Lock()
	ownerPorts, ownerNodes = ports, nodes
	ownerHealthy = map[string]bool{}
	ownerMu.Unlock()
	log.Printf("[replicas] %s is also served at %s on %s (each health-checked every %s)",
		myOverlayIP(), strings.Join(nodes, ", "), ports, replicaHealthEvery)
	go replicaHealthLoop()
}

// checkReplicaNode reports whether every TCP port of the copy on ip accepts a
// connection. The dial goes through the overlay, so it also proves the path.
func checkReplicaNode(ip string, ports replicaPorts) bool {
	for k, target := range ports {
		if k.proto != protoTCP {
			continue
		}
		if replicaDial(net.JoinHostPort(ip, strconv.Itoa(int(target))), replicaHealthTimeout) != nil {
			return false
		}
	}
	return true
}

// runReplicaHealthChecks checks every node once, in parallel, and records the
// result.
func runReplicaHealthChecks() {
	ownerMu.Lock()
	ports, nodes := ownerPorts, ownerNodes
	ownerMu.Unlock()
	results := make([]bool, len(nodes))
	var wg sync.WaitGroup
	for i, ip := range nodes {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			results[i] = checkReplicaNode(ip, ports)
		}(i, ip)
	}
	wg.Wait()
	ownerMu.Lock()
	defer ownerMu.Unlock()
	for i, ip := range nodes {
		if ownerHealthy[ip] != results[i] {
			if results[i] {
				log.Printf("[replicas] copy at %s is healthy — clients may use it", ip)
			} else {
				log.Printf("[replicas] copy at %s is NOT accepting connections — withdrawn", ip)
			}
		}
		ownerHealthy[ip] = results[i]
	}
}

func replicaHealthLoop() {
	runReplicaHealthChecks()
	t := time.NewTicker(replicaHealthEvery)
	defer t.Stop()
	for range t.C {
		runReplicaHealthChecks()
	}
}

// buildReplicaAnnounce returns the 'I' frame listing the healthy copies, or
// nil when this node publishes none. An empty list is still sent, so clients
// stop using copies at once rather than when the last announce expires.
func buildReplicaAnnounce() []byte {
	me := myOverlayIP()
	ownerMu.Lock()
	defer ownerMu.Unlock()
	if ownerPorts == nil || me == "" {
		return nil
	}
	var healthy []string
	for _, ip := range ownerNodes {
		if ownerHealthy[ip] && ip != me {
			healthy = append(healthy, ip)
		}
	}
	out := append([]byte(nil), ctlMagic...)
	out = append(out, 'I', replicaAnnounceVersion)
	return append(out, me+"|"+ownerPorts.String()+"|"+strings.Join(healthy, ",")...)
}

// ---------------------------------------------------------------------------
// Client side: which copy to use, and the rewriting
// ---------------------------------------------------------------------------

type flowKey struct {
	proto        byte
	src, dst     [4]byte
	sport, dport uint16
}

// replyKey identifies a reply from a copy: from node:nodePort to us.
type replyKey struct {
	proto     byte
	node      [4]byte
	nodePort  uint16
	local     [4]byte
	localPort uint16
}

type replicaSet struct {
	owner    [32]byte
	ports    replicaPorts
	nodes    []string
	lastSeen time.Time
}

type replicaFlow struct {
	via      string // the node the connection uses; the service address itself = the owner
	reply    replyKey
	svc      [4]byte
	svcPort  uint16
	last     time.Time
	redirect bool
}

type rttSample struct {
	ms        float64
	lastReply time.Time
}

var (
	repMu        sync.Mutex
	repServices  = map[string]*replicaSet{} // service address -> its copies
	repPreferred = map[string]string{}      // service address -> where new connections go
	repRTT       = map[[32]byte]*rttSample{}
	repFlows     = map[flowKey]*replicaFlow{}
	repReplies   = map[replyKey]*replicaFlow{}
	// repKnown is the hot-path set of service addresses with copies, so
	// ordinary packets pay one atomic load and a map miss. repRedirecting
	// lets the receive path skip parsing while no connection is redirected.
	repKnown       atomic.Pointer[map[string]struct{}]
	repRedirecting atomic.Bool

	statTxReplica atomic.Uint64
	statRxReplica atomic.Uint64

	repRejectMu  sync.Mutex
	repRejectLog = map[string]time.Time{}

	// replicaPath finds the direct, proven-live, admitted session of the node
	// AT ip (a test hook).
	replicaPath = func(ip string) (pub [32]byte, a *net.UDPAddr, s *session, ok bool) {
		if GlobalSessions == nil {
			return pub, nil, nil, false
		}
		a = ipLearning.Lookup(ip)
		if a == nil {
			return pub, nil, nil, false
		}
		s = GlobalSessions.GetByAddr(a)
		if s == nil || !s.Established() || !GlobalSessions.RouteIsLive(a) {
			return pub, nil, nil, false
		}
		pub = s.peerStatic
		if !ipBindings.IsNodeAt(pub, ip) || !admissionOK(pub, "replica") ||
			revocations.isRevoked(pub) || revoked.isRevoked(pub) {
			return pub, nil, nil, false
		}
		return pub, a, s, true
	}
	replicaOwnerOK = func(pub [32]byte, ip string) bool { return ipBindings.IsNodeAt(pub, ip) }
)

// rebuildRepKnownLocked also keeps an address whose copies were withdrawn
// while connections are still open on them, so those connections keep their
// node (see replicaRewriteOut).
func rebuildRepKnownLocked() {
	m := make(map[string]struct{}, len(repServices))
	for ip := range repServices {
		m[ip] = struct{}{}
	}
	for _, f := range repFlows {
		if f.redirect {
			m[net.IP(f.svc[:]).String()] = struct{}{}
		}
	}
	repKnown.Store(&m)
}

func isReplicatedService(ip string) bool {
	p := repKnown.Load()
	if p == nil {
		return false
	}
	_, ok := (*p)[ip]
	return ok
}

func replicaLabel(ip string) string {
	if pub, _, _, ok := replicaPath(ip); ok {
		if n := resolvePeerName(pub); n != "" {
			return n + " (" + ip + ")"
		}
	}
	return ip
}

func noteReplicaRejected(pub [32]byte, addr string) {
	k := string(pub[:]) + "|" + addr
	repRejectMu.Lock()
	defer repRejectMu.Unlock()
	if last, ok := repRejectLog[k]; ok && time.Since(last) < 10*time.Minute {
		return
	}
	repRejectLog[k] = time.Now()
	log.Printf("[replicas] ignoring copies of %s announced by key %s: it is not the node at that address",
		addr, peerKeyFingerprint(pub[:]))
}

// handleReplicaAnnounce records where copies of the sender's service run. Each
// announce REPLACES the previous one for that address.
func handleReplicaAnnounce(pub [32]byte, payload []byte) {
	if len(payload) < 1 || payload[0] != replicaAnnounceVersion {
		return
	}
	parts := strings.SplitN(string(payload[1:]), "|", 3)
	if len(parts) != 3 {
		return
	}
	ip := net.ParseIP(parts[0])
	if ip == nil || ip.To4() == nil {
		return
	}
	addr := ip.To4().String()
	if !inOverlaySubnet(addr) {
		return
	}
	if !replicaOwnerOK(pub, addr) {
		noteReplicaRejected(pub, addr)
		return
	}
	ports, err := parseReplicaPorts(parts[1])
	if err != nil {
		return
	}
	nodes := parseNodeList([]string{parts[2]}, addr)

	repMu.Lock()
	defer repMu.Unlock()
	cur := repServices[addr]
	if len(nodes) == 0 {
		if cur != nil {
			log.Printf("[replicas] %s: no healthy copies right now — every connection goes to the owner", addr)
			delete(repServices, addr)
			delete(repPreferred, addr)
			rebuildRepKnownLocked()
		}
		return
	}
	if cur == nil || strings.Join(cur.nodes, ",") != strings.Join(nodes, ",") || cur.ports.String() != ports.String() {
		log.Printf("[replicas] %s (%s) is also served at %s", addr, ports, strings.Join(nodes, ", "))
	}
	repServices[addr] = &replicaSet{owner: pub, ports: ports, nodes: nodes, lastSeen: time.Now()}
	rebuildRepKnownLocked()
}

func rttLess(a, b float64) bool {
	if a < 0 {
		return false
	}
	if b < 0 {
		return true
	}
	return a < b
}

func fmtRTT(ms float64) string {
	if ms < 0 {
		return "rtt not measured yet"
	}
	return fmt.Sprintf("%.0f ms", ms)
}

func (rs *replicaSet) offers(via, addr string) bool {
	if via == addr {
		return true
	}
	for _, n := range rs.nodes {
		if n == via {
			return true
		}
	}
	return false
}

// candidateRTTLocked returns the smoothed RTT to the node at ip, and whether
// it is usable right now. repMu held.
func candidateRTTLocked(ip string) (float64, bool) {
	if ip == myOverlayIP() {
		return rttUnknown, false
	}
	pub, _, _, ok := replicaPath(ip)
	if !ok {
		return rttUnknown, false
	}
	if r := repRTT[pub]; r != nil {
		return r.ms, true
	}
	return rttUnknown, true
}

// pickReplicaLocked chooses where a NEW connection to addr goes: the fastest
// usable of the owner and its copies, with hysteresis against the current
// choice. "" means nothing is usable. repMu held.
func pickReplicaLocked(addr string, rs *replicaSet) string {
	best, bestRTT := "", rttUnknown
	consider := func(ip string) {
		rtt, ok := candidateRTTLocked(ip)
		if !ok {
			return
		}
		// Ties go to the owner (listed first), then to the lower address.
		if best == "" || rttLess(rtt, bestRTT) {
			best, bestRTT = ip, rtt
		}
	}
	consider(addr)
	for _, n := range rs.nodes {
		consider(n)
	}
	if best == "" {
		return ""
	}
	if cur, ok := repPreferred[addr]; ok && cur != best && rs.offers(cur, addr) {
		if curRTT, usable := candidateRTTLocked(cur); usable {
			clearlyFaster := bestRTT >= 0 && curRTT >= 0 &&
				bestRTT < curRTT*replicaSwitchRatio && curRTT-bestRTT >= replicaSwitchMinMs
			newlyMeasured := curRTT < 0 && bestRTT >= 0
			if !clearlyFaster && !newlyMeasured {
				return cur
			}
		}
	}
	if prev, had := repPreferred[addr]; !had || prev != best {
		repPreferred[addr] = best
		if had {
			log.Printf("[replicas] %s: new connections now go to %s (%s), was %s",
				addr, replicaLabel(best), fmtRTT(bestRTT), replicaLabel(prev))
		} else {
			log.Printf("[replicas] %s: new connections go to %s (%s)", addr, replicaLabel(best), fmtRTT(bestRTT))
		}
	}
	return best
}

// parseFlow extracts the 5-tuple of an IPv4 TCP/UDP packet. hasPorts is false
// for anything without ports (ICMP, fragments of either kind, truncated
// headers). syn is true for a TCP SYN without ACK — the first packet of a
// connection.
func parseFlow(pkt []byte) (k flowKey, hasPorts, syn bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return k, false, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+4 {
		return k, false, false
	}
	// Fragment offset or More Fragments: a port rewrite would apply to one
	// piece only.
	if binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 {
		return k, false, false
	}
	k.proto = pkt[9]
	if k.proto != protoTCP && k.proto != protoUDP {
		return k, false, false
	}
	copy(k.src[:], pkt[12:16])
	copy(k.dst[:], pkt[16:20])
	k.sport = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
	k.dport = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	if k.proto == protoTCP && len(pkt) >= ihl+14 {
		flags := pkt[ihl+13]
		syn = flags&0x02 != 0 && flags&0x10 == 0
	}
	return k, true, syn
}

func dropFlowLocked(k flowKey, f *replicaFlow) {
	delete(repFlows, k)
	if f.redirect && repReplies[f.reply] == f {
		delete(repReplies, f.reply)
	}
}

// replicaRewriteOut decides where an outbound packet to dst goes. When a copy
// is chosen it rewrites pkt IN PLACE to that node and returns the node's
// address; the caller then routes the packet as if it had been sent there.
// ok=false means "send it to dst as usual" — not a replicated service or port,
// the owner is the fastest, or nothing else is usable.
func replicaRewriteOut(pkt []byte, dst string) (string, bool) {
	if !isReplicatedService(dst) {
		return "", false
	}
	k, hasPorts, syn := parseFlow(pkt)
	if !hasPorts {
		return "", false
	}
	now := time.Now()
	repMu.Lock()
	f := repFlows[k]
	// An open connection stays where it is for as long as that node is
	// usable, even after the owner stops listing the copy: the list steers
	// NEW connections only. A blip in the owner's health check must not reset
	// every open connection; a copy that really died resets its own, and the
	// application's retry is a new connection.
	if f != nil && !syn {
		if _, usable := candidateRTTLocked(f.via); usable || !f.redirect {
			f.last = now
			via, redirect, reply := f.via, f.redirect, f.reply
			repMu.Unlock()
			if !redirect {
				return "", false
			}
			rewriteAddrPort(pkt, true, reply.node, reply.nodePort)
			statTxReplica.Add(1)
			return via, true
		}
	}
	if f != nil {
		dropFlowLocked(k, f)
	}
	rs := repServices[dst]
	var target uint16
	ok := false
	if rs != nil && now.Sub(rs.lastSeen) <= replicaAnnounceTTL() {
		target, ok = rs.ports[portKey{k.proto, k.dport}]
	}
	if !ok {
		repMu.Unlock()
		return "", false
	}
	via := pickReplicaLocked(dst, rs)
	if via == "" {
		repMu.Unlock()
		return "", false
	}
	if len(repFlows) >= replicaMaxFlows {
		pruneReplicaFlowsLocked(now, true)
	}
	nf := &replicaFlow{via: via, svc: k.dst, svcPort: k.dport, last: now, redirect: via != dst}
	repFlows[k] = nf
	if nf.redirect {
		node, _ := ipv4To4(via)
		nf.reply = replyKey{proto: k.proto, node: node, nodePort: target, local: k.src, localPort: k.sport}
		repReplies[nf.reply] = nf
		repRedirecting.Store(true)
	}
	repMu.Unlock()
	if !nf.redirect {
		return "", false
	}
	rewriteAddrPort(pkt, true, nf.reply.node, target)
	statTxReplica.Add(1)
	return via, true
}

// replicaRewriteIn turns a reply from a copy back into a reply from the
// service address, IN PLACE, when it belongs to a connection this node
// redirected. Call it only after the packet's source was checked against the
// sender's key.
func replicaRewriteIn(pkt []byte) bool {
	if !repRedirecting.Load() {
		return false
	}
	k, hasPorts, _ := parseFlow(pkt)
	if !hasPorts {
		return false
	}
	rk := replyKey{proto: k.proto, node: k.src, nodePort: k.sport, local: k.dst, localPort: k.dport}
	repMu.Lock()
	f := repReplies[rk]
	if f == nil {
		repMu.Unlock()
		return false
	}
	f.last = time.Now()
	svc, svcPort := f.svc, f.svcPort
	repMu.Unlock()
	rewriteAddrPort(pkt, false, svc, svcPort)
	statRxReplica.Add(1)
	return true
}

// rewriteAddrPort replaces the destination (dst=true) or source address and
// port of an IPv4 TCP/UDP packet already accepted by parseFlow, and updates
// the IPv4 header and TCP/UDP checksums incrementally (RFC 1624).
func rewriteAddrPort(pkt []byte, dst bool, ip [4]byte, port uint16) {
	ihl := int(pkt[0]&0x0f) * 4
	addrOff, portOff := 12, ihl
	if dst {
		addrOff, portOff = 16, ihl+2
	}
	var oldIP [4]byte
	var oldPort, newPort [2]byte
	copy(oldIP[:], pkt[addrOff:addrOff+4])
	copy(oldPort[:], pkt[portOff:portOff+2])
	binary.BigEndian.PutUint16(newPort[:], port)
	copy(pkt[addrOff:addrOff+4], ip[:])
	copy(pkt[portOff:portOff+2], newPort[:])

	binary.BigEndian.PutUint16(pkt[10:12], csumAdjust(binary.BigEndian.Uint16(pkt[10:12]), oldIP[:], ip[:]))

	csumOff := ihl + 16
	if pkt[9] == protoUDP {
		csumOff = ihl + 6
	}
	if len(pkt) < csumOff+2 {
		return
	}
	c := binary.BigEndian.Uint16(pkt[csumOff : csumOff+2])
	if pkt[9] == protoUDP && c == 0 {
		return // UDP without a checksum
	}
	c = csumAdjust(c, oldIP[:], ip[:])
	c = csumAdjust(c, oldPort[:], newPort[:])
	if pkt[9] == protoUDP && c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(pkt[csumOff:csumOff+2], c)
}

// csumAdjust updates a ones'-complement checksum for the 16-bit words of old
// being replaced by new (RFC 1624, eqn. 3: HC' = ~(~HC + ~m + m')).
func csumAdjust(sum uint16, old, new []byte) uint16 {
	acc := uint32(^sum)
	for i := 0; i+1 < len(old); i += 2 {
		acc += uint32(^binary.BigEndian.Uint16(old[i:]))
		acc += uint32(binary.BigEndian.Uint16(new[i:]))
	}
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	return ^uint16(acc)
}

// pruneReplicaFlowsLocked drops idle flows; under pressure (full table) it
// also drops the oldest half.
func pruneReplicaFlowsLocked(now time.Time, pressure bool) {
	for k, f := range repFlows {
		idle := replicaFlowIdleOther
		if k.proto == protoTCP {
			idle = replicaFlowIdleTCP
		}
		if now.Sub(f.last) > idle {
			dropFlowLocked(k, f)
		}
	}
	if pressure && len(repFlows) >= replicaMaxFlows {
		times := make([]time.Time, 0, len(repFlows))
		for _, f := range repFlows {
			times = append(times, f.last)
		}
		sort.Slice(times, func(a, b int) bool { return times[a].Before(times[b]) })
		cut := times[len(times)/2]
		for k, f := range repFlows {
			if !f.last.After(cut) {
				dropFlowLocked(k, f)
			}
		}
	}
	repRedirecting.Store(len(repReplies) > 0)
}

// noteReplicaRTT feeds a ping round-trip (from the shared 'e'/'r' frames) in
// for any node that is a candidate.
func noteReplicaRTT(pub [32]byte, rttMs int64) {
	repMu.Lock()
	defer repMu.Unlock()
	r := repRTT[pub]
	if r == nil {
		return // not a candidate: the probe loop registers candidates
	}
	if r.ms < 0 {
		r.ms = float64(rttMs)
	} else {
		r.ms = 0.7*r.ms + 0.3*float64(rttMs)
	}
	r.lastReply = time.Now()
}

// replicaProbeLoop pings every candidate (each owner and its copies), expires
// stale announces and idle flows. Runs for the life of the process; cheap
// when no service has copies.
func replicaProbeLoop() {
	t := time.NewTicker(replicaProbeEvery)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		type target struct {
			addr *net.UDPAddr
			s    *session
		}
		var targets []target
		repMu.Lock()
		candidates := map[[32]byte]bool{}
		for addr, rs := range repServices {
			if now.Sub(rs.lastSeen) > 3*replicaAnnounceTTL() {
				log.Printf("[replicas] %s: copies not announced for %s — forgotten", addr, now.Sub(rs.lastSeen).Round(time.Second))
				delete(repServices, addr)
				delete(repPreferred, addr)
				continue
			}
			for _, ip := range append([]string{addr}, rs.nodes...) {
				pub, a, s, ok := replicaPath(ip)
				if !ok || candidates[pub] {
					continue
				}
				candidates[pub] = true
				if repRTT[pub] == nil {
					repRTT[pub] = &rttSample{ms: rttUnknown}
				}
				targets = append(targets, target{a, s})
			}
		}
		for pub := range repRTT {
			if !candidates[pub] {
				delete(repRTT, pub)
			}
		}
		pruneReplicaFlowsLocked(now, false)
		rebuildRepKnownLocked()
		repMu.Unlock()
		if len(targets) == 0 || GlobalConn == nil {
			continue
		}
		var ts [8]byte
		binary.BigEndian.PutUint64(ts[:], uint64(now.UnixNano()))
		ping := append(append(append([]byte(nil), ctlMagic...), 'e'), ts[:]...)
		for _, tg := range targets {
			_ = sendPacket(GlobalConn, tg.addr, tg.s, ping)
		}
	}
}

// ---------------------------------------------------------------------------
// Status (control API + selfcheck)
// ---------------------------------------------------------------------------

func replicaStatus() map[string]any {
	out := map[string]any{}
	ownerMu.Lock()
	if ownerPorts != nil {
		var nodes []map[string]any
		for _, ip := range ownerNodes {
			nodes = append(nodes, map[string]any{"address": ip, "healthy": ownerHealthy[ip]})
		}
		out["publishing"] = map[string]any{"address": myOverlayIP(), "ports": ownerPorts.String(), "nodes": nodes}
	}
	ownerMu.Unlock()

	repMu.Lock()
	addrs := make([]string, 0, len(repServices))
	for a := range repServices {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	var services []map[string]any
	for _, a := range addrs {
		rs := repServices[a]
		var cands []map[string]any
		for _, ip := range append([]string{a}, rs.nodes...) {
			rtt, usable := candidateRTTLocked(ip)
			var rttOut any
			if rtt >= 0 {
				rttOut = int64(rtt + 0.5)
			}
			name := ""
			if pub, _, _, ok := replicaPath(ip); ok {
				name = resolvePeerName(pub)
			}
			cands = append(cands, map[string]any{
				"address":   ip,
				"name":      name,
				"owner":     ip == a,
				"rtt_ms":    rttOut,
				"usable":    usable,
				"preferred": repPreferred[a] == ip,
			})
		}
		services = append(services, map[string]any{
			"address":    a,
			"owner_name": resolvePeerName(rs.owner),
			"ports":      rs.ports.String(),
			"age_s":      int64(time.Since(rs.lastSeen).Seconds()),
			"candidates": cands,
		})
	}
	out["services"] = services
	out["flows"] = len(repFlows)
	repMu.Unlock()
	out["tx_rewritten"] = statTxReplica.Load()
	out["rx_rewritten"] = statRxReplica.Load()
	return out
}

// replicaSelfCheckLines is the selfcheck section (empty when unused).
func replicaSelfCheckLines() []string {
	var out []string
	ownerMu.Lock()
	if ownerPorts != nil {
		var parts []string
		for _, ip := range ownerNodes {
			state := "down"
			if ownerHealthy[ip] {
				state = "ok"
			}
			parts = append(parts, ip+" "+state)
		}
		out = append(out, fmt.Sprintf("publishing copies of %s (%s): %s", myOverlayIP(), ownerPorts, strings.Join(parts, ", ")))
	}
	ownerMu.Unlock()
	repMu.Lock()
	addrs := make([]string, 0, len(repServices))
	for a := range repServices {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	for _, a := range addrs {
		var parts []string
		for _, ip := range append([]string{a}, repServices[a].nodes...) {
			mark := ""
			if repPreferred[a] == ip {
				mark = "*"
			}
			rtt, usable := candidateRTTLocked(ip)
			if !usable {
				mark += "(unusable)"
			}
			parts = append(parts, fmt.Sprintf("%s%s %s", mark, ip, fmtRTT(rtt)))
		}
		out = append(out, fmt.Sprintf("replicas of %s: %s", a, strings.Join(parts, ", ")))
	}
	if len(repFlows) > 0 || statTxReplica.Load() > 0 {
		out = append(out, fmt.Sprintf("replica flows=%d tx=%d rx=%d", len(repFlows), statTxReplica.Load(), statRxReplica.Load()))
	}
	repMu.Unlock()
	return out
}
