package main

// pubexit_client.go — USING a public exit node (Full VPN through a stranger's
// shared connection). Shared verbatim by the desktop client and the mobile
// core; platform hooks live in glue_node.go. Protocol: pubexit_proto.go.
//
// When it is used: Full VPN is on, public exits are allowed
// (use_public_exits), and either the exit is pinned to "public" or no internal
// exit (one on this device's own network) has been available for a few
// seconds. An internal exit always wins as soon as it is available.
//
// What the client protects itself against: a public exit is a stranger. It
// only ever receives internet-bound packets (never overlay or private-range
// traffic), each session uses a fresh key that identifies nothing, and every
// packet it sends back must come from a public internet address — a malicious
// exit cannot impersonate LAN or overlay hosts.

import (
	"crypto/rand"
	"encoding/binary"
	"log"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/circl/kem"
	"github.com/flynn/noise"
)

const (
	pxClientTick        = 2 * time.Second
	pxClientGrace       = 8 * time.Second // wait this long for an internal exit
	pxClientPingEvery   = 15 * time.Second
	pxClientDeadAfter   = 45 * time.Second
	pxClientAttemptTTL  = 10 * time.Second
	pxClientParallel    = 3
	pxClientMaxCands    = 64
	pxRediscoverEmpty   = time.Minute
	pxRediscoverRefresh = 10 * time.Minute
)

// pxUsePublic mirrors the use_public_exits setting.
var pxUsePublic atomic.Bool

type pxCand struct {
	ep        string
	failUntil time.Time
	rtt       time.Duration
}

type pxAttempt struct {
	ep       string
	addr     *net.UDPAddr
	hs       *noise.HandshakeState
	sk       kem.PrivateKey
	started  time.Time
	sid      uint32
	ch       *pxChannel
	finish   []byte
	finishAt time.Time
	resends  int
}

type pxActive struct {
	ep       string
	addr     *net.UDPAddr
	ch       *pxChannel
	poolIP   [4]byte
	since    time.Time
	lease    time.Duration
	lastRx   atomic.Int64
	lastPing time.Time
	pingSent atomic.Int64
	rtt      atomic.Int64 // ms
}

type pxClient struct {
	mu           sync.Mutex
	cands        map[string]*pxCand
	lastDiscover time.Time
	discovering  atomic.Bool
	attempts     map[string]*pxAttempt // by resolved address (addr.String())
	bySID        map[uint32]*pxAttempt
	active       *pxActive
	noInternal   time.Time // when an internal exit was last seen missing (zero = present)

	statSent, statRecv, statDropped atomic.Uint64
}

var gPxClient *pxClient

func startPubExitClient() *pxClient {
	c := &pxClient{
		cands:    map[string]*pxCand{},
		attempts: map[string]*pxAttempt{},
		bySID:    map[uint32]*pxAttempt{},
	}
	gPxClient = c
	go func() {
		t := time.NewTicker(pxClientTick)
		defer t.Stop()
		for range t.C {
			c.tick()
		}
	}()
	return c
}

// wanted decides whether a public exit should be in use right now. pinned and
// internal are read by the caller BEFORE taking c.mu (they take the exit
// lock; never nest it inside c.mu). Caller holds c.mu.
func (c *pxClient) wanted(now time.Time, pinned, internal bool) bool {
	if !usingExit() || !pxUsePublic.Load() {
		c.noInternal = time.Time{}
		return false
	}
	if pinned {
		return true
	}
	if internal {
		c.noInternal = time.Time{}
		return false
	}
	if c.noInternal.IsZero() {
		c.noInternal = now
	}
	return now.Sub(c.noInternal) >= pxClientGrace
}

func (c *pxClient) tick() {
	now := time.Now()
	pinned, internal := pxPinnedPublic(), pxInternalExitReady()
	c.mu.Lock()
	want := c.wanted(now, pinned, internal)
	if !want {
		act := c.active
		c.active = nil
		c.attempts = map[string]*pxAttempt{}
		c.bySID = map[uint32]*pxAttempt{}
		c.mu.Unlock()
		if act != nil {
			c.sendTo(act.addr, act.ch.seal(pxInClose, nil))
			log.Printf("[public-exit] stopped using public exit %s", act.ep)
		}
		return
	}

	// Expire attempts; resend a finish whose assignment was lost.
	for key, a := range c.attempts {
		if now.Sub(a.started) > pxClientAttemptTTL {
			delete(c.attempts, key)
			if a.sid != 0 {
				delete(c.bySID, a.sid)
			}
			c.failLocked(a.ep, time.Minute)
			continue
		}
		if a.finish != nil && now.Sub(a.finishAt) > 2*time.Second && a.resends < 3 {
			a.resends++
			a.finishAt = now
			c.sendTo(a.addr, a.finish)
		}
	}

	renew := false
	if act := c.active; act != nil {
		last := time.Unix(0, act.lastRx.Load())
		switch {
		case now.Sub(last) > pxClientDeadAfter:
			log.Printf("[public-exit] public exit %s stopped answering — finding another", act.ep)
			c.failLocked(act.ep, 2*time.Minute)
			c.active = nil
		default:
			if now.Sub(act.lastPing) >= pxClientPingEvery {
				act.lastPing = now
				act.pingSent.Store(now.UnixNano())
				var b [8]byte
				binary.BigEndian.PutUint64(b[:], uint64(now.UnixNano()))
				c.sendTo(act.addr, act.ch.seal(pxInPing, b[:]))
			}
			renew = act.lease > 0 && now.Sub(act.since) > act.lease-10*time.Minute
		}
	}
	if (c.active != nil && !renew) || len(c.attempts) > 0 {
		c.mu.Unlock()
		return
	}

	usable := c.usableLocked(now)
	needDiscover := time.Since(c.lastDiscover) > pxRediscoverRefresh ||
		(len(usable) == 0 && time.Since(c.lastDiscover) > pxRediscoverEmpty)
	c.mu.Unlock()

	if needDiscover {
		c.discover()
	}
	for i, ep := range usable {
		if i >= pxClientParallel {
			break
		}
		c.startAttempt(ep)
	}
}

// usableLocked returns candidates not in back-off, fastest known first.
func (c *pxClient) usableLocked(now time.Time) []string {
	var known, unknown []*pxCand
	for _, cd := range c.cands {
		if now.Before(cd.failUntil) {
			continue
		}
		if cd.rtt > 0 {
			known = append(known, cd)
		} else {
			unknown = append(unknown, cd)
		}
	}
	for i := 1; i < len(known); i++ {
		for j := i; j > 0 && known[j].rtt < known[j-1].rtt; j-- {
			known[j], known[j-1] = known[j-1], known[j]
		}
	}
	for i := len(unknown) - 1; i > 0; i-- { // shuffle strangers
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		j := int(n.Int64())
		unknown[i], unknown[j] = unknown[j], unknown[i]
	}
	var out []string
	for _, cd := range append(known, unknown...) {
		out = append(out, cd.ep)
	}
	return out
}

func (c *pxClient) failLocked(ep string, d time.Duration) {
	if cd, ok := c.cands[ep]; ok {
		cd.failUntil = time.Now().Add(d)
		cd.rtt = 0
	}
}

func (c *pxClient) discover() {
	if !c.discovering.CompareAndSwap(false, true) {
		return
	}
	c.mu.Lock()
	c.lastDiscover = time.Now()
	c.mu.Unlock()
	go func() {
		defer c.discovering.Store(false)
		eps := pxDiscoverDHT()
		eps = append(eps, directoryPeers("public-exit", pxDirectoryKey(), currentTrackers(), 0)...)
		c.mu.Lock()
		added := 0
		for _, ep := range eps {
			if _, ok := c.cands[ep]; ok || len(c.cands) >= pxClientMaxCands || !isValidPeer(ep) {
				continue
			}
			c.cands[ep] = &pxCand{ep: ep}
			added++
		}
		c.mu.Unlock()
		if added > 0 {
			log.Printf("[public-exit] found %d public exit node(s)", added)
		}
	}()
}

// AddCandidate adds a configured public exit endpoint ("host:port"). Unlike
// discovered endpoints it may be a private address (a public exit on the
// same LAN, or a test network).
func (c *pxClient) AddCandidate(ep string) {
	if _, _, err := net.SplitHostPort(ep); err != nil {
		return
	}
	c.mu.Lock()
	if _, ok := c.cands[ep]; !ok {
		c.cands[ep] = &pxCand{ep: ep}
	}
	c.mu.Unlock()
}

func (c *pxClient) sendTo(addr *net.UDPAddr, b []byte) {
	if conn := pxConn(); conn != nil && addr != nil {
		_, _ = conn.WriteToUDP(b, addr)
	}
}

func (c *pxClient) startAttempt(ep string) {
	addr, err := net.ResolveUDPAddr("udp", ep)
	if err != nil {
		c.mu.Lock()
		c.failLocked(ep, 10*time.Minute)
		c.mu.Unlock()
		return
	}
	static, err := pxNewStatic() // fresh per session: unlinkable
	if err != nil {
		return
	}
	hs, err := noise.NewHandshakeState(pxNoiseConfig(true, static))
	if err != nil {
		return
	}
	pk, sk, err := pxScheme().GenerateKeyPair()
	if err != nil {
		return
	}
	pkb, err := pk.MarshalBinary()
	if err != nil {
		return
	}
	msg1, _, _, err := hs.WriteMessage(nil, pkb)
	if err != nil {
		return
	}
	hello := make([]byte, pxHelloSize)
	hello[0], hello[1], hello[2] = PktPubExit, pxHello, pxVersion
	if 5+len(msg1) > len(hello) {
		return
	}
	binary.BigEndian.PutUint16(hello[3:5], uint16(len(msg1)))
	copy(hello[5:], msg1)
	c.mu.Lock()
	c.attempts[addr.String()] = &pxAttempt{ep: ep, addr: addr, hs: hs, sk: sk, started: time.Now()}
	c.mu.Unlock()
	c.sendTo(addr, hello)
}

// handleHandshake processes a HelloReply or Deny from an exit we contacted.
func (c *pxClient) handleHandshake(data []byte, raddr *net.UDPAddr) {
	key := raddr.String()
	c.mu.Lock()
	a, ok := c.attempts[key]
	if !ok || a.sid != 0 {
		c.mu.Unlock()
		return
	}
	ep := a.ep
	if data[1] == pxDeny {
		delete(c.attempts, key)
		back := 2 * time.Minute
		if len(data) >= 3 {
			switch data[2] {
			case pxDenyQuota:
				back = 30 * time.Minute
			case pxDenyDisabled, pxDenyVersion:
				back = time.Hour
			}
		}
		c.failLocked(ep, back)
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	// pxHelloReply: [type][sub][sid 4][len 2][msg2]
	if len(data) < 8 {
		return
	}
	sid := binary.BigEndian.Uint32(data[2:6])
	n := int(binary.BigEndian.Uint16(data[6:8]))
	if sid == 0 || n <= 0 || 8+n > len(data) {
		return
	}
	payload, _, _, err := a.hs.ReadMessage(nil, data[8:8+n])
	if err != nil || len(payload) < 2 || payload[0] != pxVersion {
		return
	}
	pqss, err := pxScheme().Decapsulate(a.sk, payload[1:])
	if err != nil {
		return
	}
	msg3, cs1, cs2, err := a.hs.WriteMessage(nil, []byte{pxVersion})
	if err != nil || cs1 == nil || cs2 == nil {
		return
	}
	send, recv, err := pxDeriveKeys(true, cs1, cs2, a.hs.ChannelBinding(), pqss)
	if err != nil {
		return
	}
	fin := make([]byte, 0, 8+len(msg3))
	fin = append(fin, PktPubExit, pxFinish)
	fin = binary.BigEndian.AppendUint32(fin, sid)
	fin = binary.BigEndian.AppendUint16(fin, uint16(len(msg3)))
	fin = append(fin, msg3...)

	c.mu.Lock()
	if cur, ok := c.attempts[key]; !ok || cur != a || a.sid != 0 {
		c.mu.Unlock()
		return
	}
	a.sid = sid
	a.ch = &pxChannel{sid: sid, send: send, recv: recv}
	a.finish, a.finishAt = fin, time.Now()
	c.bySID[sid] = a
	c.mu.Unlock()
	c.sendTo(a.addr, fin)
}

// handleData processes a sealed datagram from an exit we use (or are
// connecting to).
func (c *pxClient) handleData(sid uint32, data []byte, raddr *net.UDPAddr) {
	c.mu.Lock()
	act := c.active
	var a *pxAttempt
	if act == nil || act.ch.sid != sid {
		act = nil
		a = c.bySID[sid]
	}
	c.mu.Unlock()

	if act != nil {
		if act.addr.String() != raddr.String() {
			return
		}
		kind, body, err := act.ch.open(data)
		if err != nil {
			return
		}
		act.lastRx.Store(time.Now().UnixNano())
		switch kind {
		case pxInPacket:
			c.deliver(act, body)
		case pxInPong:
			if sent := act.pingSent.Load(); sent > 0 {
				act.rtt.Store(time.Since(time.Unix(0, sent)).Milliseconds())
			}
		case pxInClose:
			c.mu.Lock()
			if c.active == act {
				c.active = nil
				c.failLocked(act.ep, 2*time.Minute)
			}
			c.mu.Unlock()
			log.Printf("[public-exit] public exit %s ended the session", act.ep)
		}
		return
	}

	if a == nil || a.addr.String() != raddr.String() || a.ch == nil {
		return
	}
	kind, body, err := a.ch.open(data)
	if err != nil || kind != pxInAssign || len(body) < 10 {
		return
	}
	var pool [4]byte
	copy(pool[:], body[:4])
	lease := time.Duration(binary.BigEndian.Uint32(body[6:10])) * time.Second
	if pxIsPublicIPv4(pool) {
		return // an exit must assign a private pool address
	}
	na := &pxActive{ep: a.ep, addr: a.addr, ch: a.ch, poolIP: pool, since: time.Now(), lease: lease}
	na.lastRx.Store(time.Now().UnixNano())
	rtt := time.Since(a.started)
	na.rtt.Store(rtt.Milliseconds())

	c.mu.Lock()
	old := c.active
	c.active = na
	if cd, ok := c.cands[a.ep]; ok {
		cd.rtt = rtt
	}
	// The first exit to complete wins; the rest are abandoned (their
	// half-open state expires on the exits within seconds).
	c.attempts = map[string]*pxAttempt{}
	c.bySID = map[uint32]*pxAttempt{}
	c.mu.Unlock()
	if old != nil && old.ch.sid != na.ch.sid {
		c.sendTo(old.addr, old.ch.seal(pxInClose, nil))
	}
	log.Printf("[public-exit] internet traffic now goes through public exit %s (rtt %dms)", na.ep, rtt.Milliseconds())
	pxOnActive()
}

// pxClientSend sends an internet-bound packet through the public exit in use.
// It returns false when no public exit is ready (the caller then drops).
func pxClientSend(pkt []byte) bool {
	c := gPxClient
	if c == nil {
		return false
	}
	c.mu.Lock()
	act := c.active
	c.mu.Unlock()
	if act == nil {
		return false
	}
	p, ok := pxParse(pkt)
	if !ok || !pxIsPublicIPv4(p.dst) {
		// Never hand a stranger traffic for private or overlay addresses.
		c.statDropped.Add(1)
		return true
	}
	c.statSent.Add(1)
	c.sendTo(act.addr, act.ch.seal(pxInPacket, pkt))
	return true
}

func (c *pxClient) deliver(act *pxActive, pkt []byte) {
	p, ok := pxParse(pkt)
	if !ok || !pxIsPublicIPv4(p.src) || p.dst != act.poolIP {
		c.statDropped.Add(1)
		return
	}
	self := net.ParseIP(pxSelfIP()).To4()
	if self == nil {
		return
	}
	var me [4]byte
	copy(me[:], self)
	buf := append([]byte(nil), pkt...)
	if !pxRewrite(buf, false, me) {
		c.statDropped.Add(1)
		return
	}
	c.statRecv.Add(1)
	pxWriteTUN(buf)
}

// pxActiveReady reports whether a public exit session is carrying traffic.
func pxActiveReady() bool {
	c := gPxClient
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active != nil
}

// pxClientStatus is the status view for the apps.
type pxClientStatus struct {
	Allowed   bool   `json:"allowed"`
	Active    bool   `json:"active"`
	Endpoint  string `json:"endpoint,omitempty"`
	RTTms     int64  `json:"rtt_ms,omitempty"`
	Since     int64  `json:"since,omitempty"`
	Known     int    `json:"known"`
	Sent      uint64 `json:"packets_sent"`
	Received  uint64 `json:"packets_received"`
	Dropped   uint64 `json:"packets_dropped"`
	Searching bool   `json:"searching"`
}

func pubExitClientStatus() pxClientStatus {
	st := pxClientStatus{Allowed: pxUsePublic.Load()}
	c := gPxClient
	if c == nil {
		return st
	}
	c.mu.Lock()
	st.Known = len(c.cands)
	if a := c.active; a != nil {
		st.Active, st.Endpoint, st.Since = true, a.ep, a.since.Unix()
		st.RTTms = a.rtt.Load()
	}
	st.Searching = c.active == nil && (len(c.attempts) > 0 || c.discovering.Load())
	c.mu.Unlock()
	st.Sent, st.Received, st.Dropped = c.statSent.Load(), c.statRecv.Load(), c.statDropped.Load()
	return st
}
