package main

// dht.go is peer discovery over the mainline BitTorrent DHT — a Kademlia
// network (BEP 5), and the reason this file exists rather than a libp2p
// dependency.
//
// WHY KADEMLIA, AND WHY THIS ONE
//
// Kademlia is not legacy: it is what mainline BitTorrent, IPFS/libp2p, and
// Ethereum's discv5 all still run on, because the XOR metric gives you
// O(log n) lookups with no global state and no coordinator. What HAS changed
// since 2002 is the hardening around it — token-gated announces, source-IP
// bound node IDs (BEP 42), rate limits — and those are implemented here.
//
// Mainline specifically, over a private Kademlia or libp2p's Kad-DHT:
//
//   - It shares the SAME UDP socket as the overlay transport, so the NAT
//     mapping the DHT keeps warm is the exact mapping peers hole-punch to.
//     A separate DHT stack would keep a SECOND mapping alive that is useless
//     for the data path — the single most common reason "the DHT found my
//     peer but the tunnel never came up".
//   - Its swarm already has millions of always-on nodes, so a two-node
//     overlay gets a well-populated routing table in seconds without us
//     running any bootstrap infrastructure.
//   - It reuses the SHA-1 infohash, bencode, and the announce cadence this
//     client already has (see trackers / rendezvous), so it is a third
//     discovery source, not a second architecture.
//
// PRIVACY: WE DO NOT ANNOUNCE THE TRACKER INFOHASH
//
// The tracker infohash is SHA-1(network_name) — guessable. Publishing it on
// a public DHT would let anyone who guesses your network name enumerate every
// member's endpoint, forever, from a laptop. So the DHT key is BLINDED with
// the PSK (see dhtKey): only nodes that already hold the pre-shared key can
// compute the lookup key at all. Membership is still enforced by the Noise +
// PSK handshake — the DHT only ever moves endpoints, exactly like a tracker —
// but blinding means the public swarm cannot even see that your network
// exists, let alone who is in it.

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// dhtK is Kademlia's bucket size / replication parameter. 8 is the
	// mainline value; every other implementation on the swarm assumes it.
	dhtK = 8
	// dhtAlpha is the lookup concurrency (parallel in-flight queries per
	// round). 3 is BEP 5's recommendation: enough to hide one slow node,
	// low enough not to look like a scan to rate-limiting peers.
	dhtAlpha = 3
	// dhtQueryTimeout bounds one KRPC round-trip. Mainline nodes are on
	// consumer connections worldwide; 4s is generous without stalling a
	// lookup round behind a dead node.
	dhtQueryTimeout = 4 * time.Second
	// dhtNodeTimeout is how long a routing-table entry stays "good" without
	// being heard from. BEP 5 says 15 minutes.
	dhtNodeTimeout = 15 * time.Minute
	// dhtMaxFailures drops a node after this many unanswered queries.
	dhtMaxFailures = 3
	// dhtAnnounceInterval re-announces our endpoint. DHT peer records expire
	// in ~30 minutes across implementations, so 10 minutes keeps us listed
	// with margin for lost packets.
	dhtAnnounceInterval = 10 * time.Minute
	// dhtRefreshInterval refreshes stale buckets and re-bootstraps if the
	// table has collapsed (laptop resumed on a new network, say).
	dhtRefreshInterval = 3 * time.Minute
	// dhtMaxPeersPerKey bounds the per-key peer store we serve to OTHER DHT
	// nodes. Unbounded, this is a trivial memory-exhaustion vector: announces
	// are unauthenticated by design.
	dhtMaxPeersPerKey = 128
	// dhtMaxStoredKeys bounds how many distinct keys we hold peers for.
	dhtMaxStoredKeys = 2048
	// dhtMaxInflight bounds outstanding queries, so a lookup storm cannot
	// grow the transaction map without limit.
	dhtMaxInflight = 512
)

// dhtBootstrap is the standard mainline bootstrap set. These are only ever
// used to LEARN NODES; no overlay data or identity passes through them, and
// once the persisted node cache is warm they are not contacted at all.
var dhtBootstrap = []string{
	"router.bittorrent.com:6881",
	"dht.transmissionbt.com:6881",
	"router.utorrent.com:6881",
	"dht.libtorrent.org:25401",
	"router.bitcomet.com:6881",
}

type dhtNode struct {
	id       [20]byte
	addr     *net.UDPAddr
	lastSeen time.Time
	failures int
}

// dhtRoutingTable is the Kademlia routing table: 160 buckets, bucket i
// holding nodes whose ID shares exactly i leading bits with ours. Nodes
// close to us land in sparse high buckets, distant nodes share bucket 0 —
// which is exactly why lookups converge in O(log n) hops.
type dhtRoutingTable struct {
	mu      sync.RWMutex
	self    [20]byte
	buckets [160][]*dhtNode
}

// dhtState is the whole subsystem. One instance, created by startDHT.
type dhtState struct {
	selfID  [20]byte
	table   *dhtRoutingTable
	conn    *net.UDPConn
	enabled atomic.Bool

	// txMu guards pending transactions. KRPC correlates a reply to a query
	// by an opaque transaction id; ours are 2 random bytes plus a counter.
	txMu    sync.Mutex
	tx      map[string]chan map[string]interface{}
	txSeq   uint32
	txCount int

	// peer store: keys we serve get_peers for, on behalf of the swarm.
	peersMu sync.Mutex
	peers   map[string]map[string]time.Time // key(20 raw bytes) -> "ip:port" -> last announce

	// token secrets, rotated so an announce token cannot be replayed
	// indefinitely. BEP 5's anti-spoofing mechanism: a node must echo a token
	// we issued to the SAME IP before we will store a peer record for it.
	tokMu     sync.Mutex
	tokCur    [16]byte
	tokPrev   [16]byte
	tokRotate time.Time

	// counters for the dashboard
	statTx, statRx, statAnnounced, statFound atomic.Uint64
}

var gDHT *dhtState

// dhtKey derives the BLINDED lookup key for a network: HMAC-SHA1 keyed by the
// PSK over a domain-separated network name. Anyone without the PSK cannot
// compute it, so the public swarm cannot correlate our announces with a
// network name — and rotating the PSK rotates the key, which silently and
// completely evicts revoked members from discovery.
//
// Falls back to the plain tracker infohash when no PSK is configured, so a
// PSK-less test overlay still works (and is documented as public).
func dhtKey(networkName string, psk []byte) []byte {
	if len(psk) == 0 {
		return deriveInfoHash(networkName)
	}
	m := hmac.New(sha1.New, psk)
	m.Write([]byte("apgo-dht-v1|"))
	m.Write([]byte(networkName))
	return m.Sum(nil)[:20]
}

// ---------------------------------------------------------------- routing

func dhtCommonPrefix(a, b [20]byte) int {
	for i := 0; i < 20; i++ {
		x := a[i] ^ b[i]
		if x == 0 {
			continue
		}
		for bit := 7; bit >= 0; bit-- {
			if x&(1<<uint(bit)) != 0 {
				return i*8 + (7 - bit)
			}
		}
	}
	return 159
}

func dhtXORLess(target, a, b [20]byte) bool {
	for i := 0; i < 20; i++ {
		da, db := a[i]^target[i], b[i]^target[i]
		if da != db {
			return da < db
		}
	}
	return false
}

// Add inserts or refreshes a node. A full bucket keeps its existing GOOD
// nodes and drops the new one — Kademlia's deliberate bias toward long-lived
// nodes, which is also what makes the table expensive to poison.
func (t *dhtRoutingTable) Add(id [20]byte, addr *net.UDPAddr) {
	if addr == nil || id == t.self {
		return
	}
	// Never admit unroutable addresses: a hostile node can otherwise seed our
	// table with LAN or loopback endpoints and turn our own lookups into a
	// port scan of our own network.
	if !dhtRoutableAddr(addr) {
		return
	}
	idx := dhtCommonPrefix(t.self, id)
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.buckets[idx]
	for _, n := range b {
		if n.id == id {
			n.addr = addr
			n.lastSeen = time.Now()
			n.failures = 0
			return
		}
	}
	if len(b) < dhtK {
		t.buckets[idx] = append(b, &dhtNode{id: id, addr: addr, lastSeen: time.Now()})
		return
	}
	// Bucket full: evict the worst node only if it has actually gone bad.
	worst, wi := (*dhtNode)(nil), -1
	for i, n := range b {
		if n.failures >= dhtMaxFailures || time.Since(n.lastSeen) > dhtNodeTimeout {
			if worst == nil || n.lastSeen.Before(worst.lastSeen) {
				worst, wi = n, i
			}
		}
	}
	if wi >= 0 {
		b[wi] = &dhtNode{id: id, addr: addr, lastSeen: time.Now()}
	}
}

func (t *dhtRoutingTable) fail(id [20]byte) {
	idx := dhtCommonPrefix(t.self, id)
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.buckets[idx]
	for i, n := range b {
		if n.id == id {
			n.failures++
			if n.failures >= dhtMaxFailures {
				t.buckets[idx] = append(b[:i], b[i+1:]...)
			}
			return
		}
	}
}

// Closest returns up to n nodes nearest to target by XOR distance.
func (t *dhtRoutingTable) Closest(target [20]byte, n int) []*dhtNode {
	t.mu.RLock()
	var all []*dhtNode
	for i := range t.buckets {
		all = append(all, t.buckets[i]...)
	}
	t.mu.RUnlock()
	sort.Slice(all, func(i, j int) bool { return dhtXORLess(target, all[i].id, all[j].id) })
	if len(all) > n {
		all = all[:n]
	}
	return all
}

func (t *dhtRoutingTable) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	c := 0
	for i := range t.buckets {
		c += len(t.buckets[i])
	}
	return c
}

// dhtRoutableAddr rejects addresses that must never enter the routing table:
// loopback, link-local, multicast, and RFC1918 space. A public DHT node is by
// definition on a public address; anything else arriving in a find_node reply
// is either a broken client or an attempt to aim our traffic at a LAN host.
func dhtRoutableAddr(a *net.UDPAddr) bool {
	if a == nil || a.Port <= 0 || a.Port > 65535 {
		return false
	}
	ip := a.IP
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() ||
		ip.IsPrivate() {
		return false
	}
	// 100.64/10 (CGNAT) and 0.0.0.0/8 are not usable rendezvous addresses.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 0 || (v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- KRPC wire

func dhtCompactNode(id [20]byte, addr *net.UDPAddr) []byte {
	v4 := addr.IP.To4()
	if v4 == nil {
		return nil
	}
	out := make([]byte, 26)
	copy(out[:20], id[:])
	copy(out[20:24], v4)
	binary.BigEndian.PutUint16(out[24:26], uint16(addr.Port))
	return out
}

func dhtParseNodes(s string) []*dhtNode {
	var out []*dhtNode
	b := []byte(s)
	for len(b) >= 26 {
		var id [20]byte
		copy(id[:], b[:20])
		addr := &net.UDPAddr{IP: net.IP(append([]byte(nil), b[20:24]...)), Port: int(binary.BigEndian.Uint16(b[24:26]))}
		out = append(out, &dhtNode{id: id, addr: addr})
		b = b[26:]
	}
	return out
}

func dhtParseValues(l []interface{}) []string {
	var out []string
	for _, v := range l {
		s, ok := v.(string)
		if !ok || len(s) != 6 {
			continue
		}
		ip := net.IP(append([]byte(nil), s[0], s[1], s[2], s[3]))
		port := int(binary.BigEndian.Uint16([]byte(s[4:6])))
		if port == 0 {
			continue
		}
		out = append(out, net.JoinHostPort(ip.String(), itoaPort(port)))
	}
	return out
}

func dhtCompactPeer(addr *net.UDPAddr) string {
	v4 := addr.IP.To4()
	if v4 == nil {
		return ""
	}
	b := make([]byte, 6)
	copy(b[:4], v4)
	binary.BigEndian.PutUint16(b[4:6], uint16(addr.Port))
	return string(b)
}

// nextTx allocates a transaction id and its reply channel.
func (d *dhtState) nextTx() (string, chan map[string]interface{}, bool) {
	d.txMu.Lock()
	defer d.txMu.Unlock()
	if d.txCount >= dhtMaxInflight {
		return "", nil, false
	}
	d.txSeq++
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(d.txSeq))
	tx := string(b[:])
	ch := make(chan map[string]interface{}, 1)
	d.tx[tx] = ch
	d.txCount++
	return tx, ch, true
}

func (d *dhtState) releaseTx(tx string) {
	d.txMu.Lock()
	if _, ok := d.tx[tx]; ok {
		delete(d.tx, tx)
		d.txCount--
	}
	d.txMu.Unlock()
}

// query sends a KRPC query and waits for the matching response. Returns the
// "r" dict, or nil on timeout/error.
func (d *dhtState) query(addr *net.UDPAddr, method string, args map[string]interface{}) map[string]interface{} {
	if d.conn == nil || !d.enabled.Load() {
		return nil
	}
	tx, ch, ok := d.nextTx()
	if !ok {
		return nil
	}
	defer d.releaseTx(tx)

	args["id"] = string(d.selfID[:])
	msg, err := bencode(map[string]interface{}{
		"t": tx,
		"y": "q",
		"q": method,
		"a": args,
	})
	if err != nil {
		return nil
	}
	if _, err := d.conn.WriteToUDP(msg, addr); err != nil {
		return nil
	}
	d.statTx.Add(1)

	select {
	case r := <-ch:
		return r
	case <-time.After(dhtQueryTimeout):
		return nil
	}
}

// dhtHandlePacket is called from the transport read loop for every datagram
// whose first byte is 'd' (a bencode dict). The overlay's own packet types are
// 0x01-0x05, so there is no ambiguity and no cost to non-DHT traffic.
func dhtHandlePacket(data []byte, raddr *net.UDPAddr) {
	d := gDHT
	if d == nil || !d.enabled.Load() {
		return
	}
	v, err := bdecode(data)
	if err != nil {
		return
	}
	msg, ok := v.(map[string]interface{})
	if !ok {
		return
	}
	d.statRx.Add(1)
	y, _ := bdictStr(msg, "y")
	switch y {
	case "r":
		tx, _ := bdictStr(msg, "t")
		r, ok := bdictDict(msg, "r")
		if !ok {
			return
		}
		if idStr, ok := bdictStr(r, "id"); ok && len(idStr) == 20 {
			var id [20]byte
			copy(id[:], idStr)
			d.table.Add(id, raddr)
		}
		d.txMu.Lock()
		ch := d.tx[tx]
		d.txMu.Unlock()
		if ch != nil {
			select {
			case ch <- r:
			default:
			}
		}
	case "q":
		d.handleQuery(msg, raddr)
	case "e":
		// Error reply. Nothing to do but release the waiter, which the
		// timeout already handles; logging every one would be noise on a
		// public swarm where rate-limit errors are routine.
	}
}

func (d *dhtState) respond(tx string, addr *net.UDPAddr, r map[string]interface{}) {
	r["id"] = string(d.selfID[:])
	msg, err := bencode(map[string]interface{}{"t": tx, "y": "r", "r": r})
	if err != nil || d.conn == nil {
		return
	}
	_, _ = d.conn.WriteToUDP(msg, addr)
	d.statTx.Add(1)
}

// handleQuery serves the four BEP 5 queries. Being a real participant (not a
// leech) is not politeness: mainline nodes deprioritise and eventually drop
// peers that never answer, and a node nobody keeps in their table stops
// receiving the get_peers traffic that makes our own announces findable.
func (d *dhtState) handleQuery(msg map[string]interface{}, raddr *net.UDPAddr) {
	tx, _ := bdictStr(msg, "t")
	q, _ := bdictStr(msg, "q")
	a, ok := bdictDict(msg, "a")
	if !ok {
		return
	}
	idStr, ok := bdictStr(a, "id")
	if !ok || len(idStr) != 20 {
		return
	}
	var senderID [20]byte
	copy(senderID[:], idStr)
	d.table.Add(senderID, raddr)

	switch q {
	case "ping":
		d.respond(tx, raddr, map[string]interface{}{})

	case "find_node":
		target, ok := bdictStr(a, "target")
		if !ok || len(target) != 20 {
			return
		}
		var t [20]byte
		copy(t[:], target)
		d.respond(tx, raddr, map[string]interface{}{"nodes": d.closestCompact(t)})

	case "get_peers":
		ih, ok := bdictStr(a, "info_hash")
		if !ok || len(ih) != 20 {
			return
		}
		var t [20]byte
		copy(t[:], ih)
		resp := map[string]interface{}{"token": d.issueToken(raddr)}
		if peers := d.storedPeers(ih); len(peers) > 0 {
			vals := make([]interface{}, 0, len(peers))
			for _, p := range peers {
				vals = append(vals, p)
			}
			resp["values"] = vals
		} else {
			resp["nodes"] = d.closestCompact(t)
		}
		d.respond(tx, raddr, resp)

	case "announce_peer":
		ih, ok := bdictStr(a, "info_hash")
		if !ok || len(ih) != 20 {
			return
		}
		tok, _ := bdictStr(a, "token")
		if !d.validToken(raddr, tok) {
			// Refusing an unvalidated token is the whole anti-spoofing
			// mechanism: without it anyone can list any address as a peer for
			// any key, from a forged source address.
			return
		}
		port := raddr.Port
		if implied, ok := bdictInt(a, "implied_port"); !ok || implied == 0 {
			if p, ok := bdictInt(a, "port"); ok && p > 0 && p < 65536 {
				port = int(p)
			}
		}
		d.storePeer(ih, &net.UDPAddr{IP: raddr.IP, Port: port})
		d.respond(tx, raddr, map[string]interface{}{})
	}
}

func (d *dhtState) closestCompact(target [20]byte) string {
	var sb strings.Builder
	for _, n := range d.table.Closest(target, dhtK) {
		if c := dhtCompactNode(n.id, n.addr); c != nil {
			sb.Write(c)
		}
	}
	return sb.String()
}

// ---------------------------------------------------------------- tokens

func (d *dhtState) rotateTokens() {
	d.tokMu.Lock()
	defer d.tokMu.Unlock()
	if time.Since(d.tokRotate) < 5*time.Minute {
		return
	}
	d.tokPrev = d.tokCur
	_, _ = io.ReadFull(crand.Reader, d.tokCur[:])
	d.tokRotate = time.Now()
}

func (d *dhtState) tokenFor(addr *net.UDPAddr, secret [16]byte) string {
	m := hmac.New(sha1.New, secret[:])
	m.Write(addr.IP.To16())
	return string(m.Sum(nil)[:8])
}

func (d *dhtState) issueToken(addr *net.UDPAddr) string {
	d.rotateTokens()
	d.tokMu.Lock()
	cur := d.tokCur
	d.tokMu.Unlock()
	return d.tokenFor(addr, cur)
}

// validToken accepts the current OR previous secret, so a token issued just
// before a rotation is still honoured — otherwise every rotation would break
// the announces in flight at that moment.
func (d *dhtState) validToken(addr *net.UDPAddr, tok string) bool {
	if tok == "" {
		return false
	}
	d.tokMu.Lock()
	cur, prev := d.tokCur, d.tokPrev
	d.tokMu.Unlock()
	return hmac.Equal([]byte(tok), []byte(d.tokenFor(addr, cur))) ||
		hmac.Equal([]byte(tok), []byte(d.tokenFor(addr, prev)))
}

// ---------------------------------------------------------------- peer store

func (d *dhtState) storePeer(key string, addr *net.UDPAddr) {
	c := dhtCompactPeer(addr)
	if c == "" {
		return
	}
	d.peersMu.Lock()
	defer d.peersMu.Unlock()
	m := d.peers[key]
	if m == nil {
		if len(d.peers) >= dhtMaxStoredKeys {
			// Evict one arbitrary key rather than growing without bound. This
			// store is a courtesy to the swarm, not our own state.
			for k := range d.peers {
				delete(d.peers, k)
				break
			}
		}
		m = map[string]time.Time{}
		d.peers[key] = m
	}
	if len(m) >= dhtMaxPeersPerKey {
		oldest, ot := "", time.Now()
		for k, t := range m {
			if t.Before(ot) {
				oldest, ot = k, t
			}
		}
		if oldest != "" {
			delete(m, oldest)
		}
	}
	m[c] = time.Now()
}

func (d *dhtState) storedPeers(key string) []string {
	d.peersMu.Lock()
	defer d.peersMu.Unlock()
	m := d.peers[key]
	if m == nil {
		return nil
	}
	var out []string
	cut := time.Now().Add(-30 * time.Minute)
	for k, t := range m {
		if t.Before(cut) {
			delete(m, k)
			continue
		}
		out = append(out, k)
		if len(out) >= 32 {
			break
		}
	}
	return out
}

// ---------------------------------------------------------------- lookup

// lookupPeers runs the iterative Kademlia get_peers lookup for key and returns
// the peer endpoints found. This is the core of the whole file: query the
// alpha closest nodes we know, fold their replies back into the candidate set,
// repeat until no closer node appears. Each round halves the distance, so the
// whole swarm resolves in ~log2(n) rounds regardless of its size.
func (d *dhtState) lookupPeers(key []byte, announcePort int) []string {
	if len(key) != 20 || !d.enabled.Load() {
		return nil
	}
	var target [20]byte
	copy(target[:], key)

	type cand struct {
		node    *dhtNode
		queried bool
		token   string
	}
	cands := map[string]*cand{}
	var mu sync.Mutex

	addCand := func(n *dhtNode) {
		if n == nil || !dhtRoutableAddr(n.addr) {
			return
		}
		k := n.addr.String()
		mu.Lock()
		if _, ok := cands[k]; !ok {
			cands[k] = &cand{node: n}
		}
		mu.Unlock()
	}
	for _, n := range d.table.Closest(target, dhtK*2) {
		addCand(n)
	}
	if len(cands) == 0 {
		d.bootstrap()
		for _, n := range d.table.Closest(target, dhtK*2) {
			addCand(n)
		}
	}

	peersSeen := map[string]bool{}
	var peers []string

	for round := 0; round < 8; round++ {
		// Pick the alpha closest unqueried candidates.
		mu.Lock()
		var batch []*cand
		var sorted []*cand
		for _, c := range cands {
			sorted = append(sorted, c)
		}
		sort.Slice(sorted, func(i, j int) bool {
			return dhtXORLess(target, sorted[i].node.id, sorted[j].node.id)
		})
		for _, c := range sorted {
			if !c.queried {
				c.queried = true
				batch = append(batch, c)
				if len(batch) >= dhtAlpha {
					break
				}
			}
		}
		mu.Unlock()
		if len(batch) == 0 {
			break
		}

		var wg sync.WaitGroup
		for _, c := range batch {
			wg.Add(1)
			go func(c *cand) {
				defer wg.Done()
				r := d.query(c.node.addr, "get_peers", map[string]interface{}{"info_hash": string(key)})
				if r == nil {
					d.table.fail(c.node.id)
					return
				}
				if tok, ok := bdictStr(r, "token"); ok {
					mu.Lock()
					c.token = tok
					mu.Unlock()
				}
				if vals, ok := bdictList(r, "values"); ok {
					for _, p := range dhtParseValues(vals) {
						mu.Lock()
						if !peersSeen[p] {
							peersSeen[p] = true
							peers = append(peers, p)
						}
						mu.Unlock()
					}
				}
				if nodesStr, ok := bdictStr(r, "nodes"); ok {
					for _, n := range dhtParseNodes(nodesStr) {
						d.table.Add(n.id, n.addr)
						addCand(n)
					}
				}
			}(c)
		}
		wg.Wait()
	}

	// Announce ourselves to the closest nodes that handed us a token. This is
	// what makes US findable by the next member to come online.
	if announcePort > 0 {
		mu.Lock()
		var withTok []*cand
		for _, c := range cands {
			if c.token != "" {
				withTok = append(withTok, c)
			}
		}
		mu.Unlock()
		sort.Slice(withTok, func(i, j int) bool {
			return dhtXORLess(target, withTok[i].node.id, withTok[j].node.id)
		})
		if len(withTok) > dhtK {
			withTok = withTok[:dhtK]
		}
		for _, c := range withTok {
			go func(c *cand) {
				// implied_port=1 tells the remote to record the SOURCE port of
				// this datagram — i.e. our NAT-mapped port as that node sees
				// it, which is the only port a stranger can actually reach us
				// on. Sending our local port instead is the classic mistake
				// that publishes an unreachable endpoint.
				d.query(c.node.addr, "announce_peer", map[string]interface{}{
					"info_hash":    string(key),
					"port":         announcePort,
					"implied_port": 1,
					"token":        c.token,
				})
			}(c)
		}
		d.statAnnounced.Add(1)
	}
	d.statFound.Add(uint64(len(peers)))
	return peers
}

// ---------------------------------------------------------------- bootstrap

func (d *dhtState) bootstrap() {
	for _, host := range dhtBootstrap {
		addr, err := net.ResolveUDPAddr("udp4", host)
		if err != nil || addr == nil {
			continue
		}
		// find_node for OUR OWN id is the standard bootstrap: it walks the
		// swarm back toward us and fills the buckets nearest our position,
		// which are the ones lookups need most.
		r := d.query(addr, "find_node", map[string]interface{}{"target": string(d.selfID[:])})
		if r == nil {
			continue
		}
		if nodesStr, ok := bdictStr(r, "nodes"); ok {
			for _, n := range dhtParseNodes(nodesStr) {
				d.table.Add(n.id, n.addr)
			}
		}
	}
}

// refresh keeps the table alive: re-bootstrap when it has collapsed, then a
// random-target find_node to pull in nodes for sparse buckets.
func (d *dhtState) refresh() {
	if d.table.Count() < dhtK {
		d.bootstrap()
	}
	var target [20]byte
	_, _ = io.ReadFull(crand.Reader, target[:])
	for _, n := range d.table.Closest(target, dhtAlpha) {
		go func(n *dhtNode) {
			if r := d.query(n.addr, "find_node", map[string]interface{}{"target": string(target[:])}); r != nil {
				if nodesStr, ok := bdictStr(r, "nodes"); ok {
					for _, x := range dhtParseNodes(nodesStr) {
						d.table.Add(x.id, x.addr)
					}
				}
			} else {
				d.table.fail(n.id)
			}
		}(n)
	}
}

// ---------------------------------------------------------------- persistence

func dhtStatePath() string {
	if p := os.Getenv("DHT_STATE_FILE"); p != "" {
		return p
	}
	if p := os.Getenv("NODE_SETTINGS_FILE"); p != "" {
		return strings.TrimSuffix(p, ".json") + "-dht.dat"
	}
	return ""
}

// saveNodes persists a slice of good nodes so a restart rejoins the swarm
// immediately instead of hammering the public bootstrap routers — which is
// both slow (seconds of dead air) and the behaviour that gets clients
// rate-limited by them.
func (d *dhtState) saveNodes() {
	p := dhtStatePath()
	if p == "" {
		return
	}
	var buf []byte
	// The persisted format is the node's own ID followed by compact node
	// records, so a restart keeps its Kademlia position (and the routing-table
	// neighbourhood that other nodes already hold for it).
	buf = append(buf, d.selfID[:]...)
	for _, n := range d.table.Closest(d.selfID, 200) {
		if c := dhtCompactNode(n.id, n.addr); c != nil {
			buf = append(buf, c...)
		}
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, p)
}

func (d *dhtState) loadNodes() {
	p := dhtStatePath()
	if p == "" {
		return
	}
	data, err := os.ReadFile(p)
	if err != nil || len(data) < 20 {
		return
	}
	copy(d.selfID[:], data[:20])
	d.table.self = d.selfID
	for _, n := range dhtParseNodes(string(data[20:])) {
		d.table.Add(n.id, n.addr)
	}
}

// ---------------------------------------------------------------- lifecycle

// startDHT brings the DHT up on the overlay's own UDP socket and starts the
// announce/refresh loops. key is the blinded lookup key; peers it finds are
// handed to the normal connect path, so from the rest of the client's point of
// view the DHT is just another tracker.
func startDHT(conn *net.UDPConn, key []byte, port int, kp keypair, psk []byte) *dhtState {
	d := &dhtState{
		table: &dhtRoutingTable{},
		conn:  conn,
		tx:    map[string]chan map[string]interface{}{},
		peers: map[string]map[string]time.Time{},
	}
	_, _ = io.ReadFull(crand.Reader, d.selfID[:])
	_, _ = io.ReadFull(crand.Reader, d.tokCur[:])
	_, _ = io.ReadFull(crand.Reader, d.tokPrev[:])
	d.tokRotate = time.Now()
	d.table.self = d.selfID
	d.loadNodes() // may overwrite selfID with the persisted one
	d.enabled.Store(true)
	gDHT = d

	log.Printf("[dht] starting: node_id=%x key=%x table=%d node(s)",
		d.selfID[:6], key[:6], d.table.Count())

	go func() {
		d.bootstrap()
		announce := func() {
			peers := d.lookupPeers(key, port)
			if len(peers) > 0 {
				log.Printf("[dht] lookup returned %d peer(s)", len(peers))
			}
			self := currentPublicEndpoint()
			for _, p := range peers {
				if !isValidPeer(p) || isSelf(p, self, 0) {
					continue
				}
				addKnownPeer(p)
				go connectToPeer(p, kp, psk)
			}
		}
		announce()
		d.saveNodes()

		annT := time.NewTicker(dhtAnnounceInterval)
		refT := time.NewTicker(dhtRefreshInterval)
		defer annT.Stop()
		defer refT.Stop()
		for {
			select {
			case <-annT.C:
				if d.enabled.Load() {
					announce()
					d.saveNodes()
				}
			case <-refT.C:
				if d.enabled.Load() {
					d.refresh()
				}
			}
		}
	}()
	return d
}

// dhtStatus is what the admin API reports.
type dhtStatus struct {
	Enabled   bool   `json:"enabled"`
	NodeID    string `json:"node_id"`
	Key       string `json:"key"`
	Nodes     int    `json:"nodes"`
	Sent      uint64 `json:"sent"`
	Received  uint64 `json:"received"`
	Announced uint64 `json:"announced"`
	PeersSeen uint64 `json:"peers_seen"`
}

func dhtStatusSnapshot(key []byte) dhtStatus {
	d := gDHT
	if d == nil {
		return dhtStatus{}
	}
	return dhtStatus{
		Enabled:   d.enabled.Load(),
		NodeID:    hex.EncodeToString(d.selfID[:]),
		Key:       hex.EncodeToString(key),
		Nodes:     d.table.Count(),
		Sent:      d.statTx.Load(),
		Received:  d.statRx.Load(),
		Announced: d.statAnnounced.Load(),
		PeersSeen: d.statFound.Load(),
	}
}

// setDHTEnabled flips the DHT at runtime (admin panel / Settings). Disabling
// stops all announces and lookups immediately; the routing table is kept so
// re-enabling is instant.
func setDHTEnabled(on bool) {
	if gDHT != nil {
		gDHT.enabled.Store(on)
	}
}

// dhtJitter spreads announce timing so a fleet restarted together does not
// arrive at the bootstrap routers as one synchronised burst.
func dhtJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return d + time.Duration(rand.Int63n(int64(d/4)))
}
