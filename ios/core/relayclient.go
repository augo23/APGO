package overlaymobile

// relayclient.go — using a public relay from the mobile core.
//
// This is a port of client/relayclient.go. It is kept deliberately close to
// that file, line for line where the languages allow, so the two can be
// diffed when either changes. The differences are forced and are listed here
// rather than scattered as surprises:
//
//   1. NO SERVER HALF. A phone must never BE a relay: it would spend a
//      stranger's traffic out of the user's battery and cellular plan. Only
//      the client half is ported; publicrelay.go stays desktop-only.
//   2. DISCOVERY VIA TRACKERS, NOT THE DHT. The mobile core has no DHT (see
//      relaydirectory.go for why, and for the tracker-based directory that
//      replaces it).
//   3. UNTYPED CONSTANTS. gobind rejects byte-typed constants — the same
//      reason sessions.go spells PktData as an untyped 0x04 — so the relay
//      protocol constants are untyped here while the wire bytes are
//      identical.
//
// WHY THIS FILE HAD TO EXIST
//
// Its absence was the whole bug. A phone on a cellular carrier sits behind
// symmetric NAT; a laptop at home sits behind a port-restricted router.
// Neither can punch the other (see relaypolicy.go). Relay is the only path
// that can work — and the mobile core could not so much as FIND a relay, let
// alone open a circuit through one. So it did the only thing left: retried
// direct handshakes against a carrier port that had already moved, for as
// long as the app stayed open. The desktop side held relay reservations the
// entire time, waiting for a peer that was structurally incapable of
// answering.
//
// HOW A RELAYED PEER LOOKS LIKE A DIRECT ONE
//
// Sessions, routing, admission control, PEX and the status API are all keyed
// by *net.UDPAddr. Rather than thread a transport abstraction through every
// one of them, a circuit is given a SYNTHETIC ADDRESS: 240.<24-bit circuit
// id>, out of 240.0.0.0/4, which is reserved, never routed, and cannot
// collide with a real peer endpoint. Two pieces of plumbing make it work:
//
//	send: overlayWriteTo() recognises a 240/4 destination and wraps the frame
//	      in a relay DATA message addressed to the relay instead.
//	recv: an arriving DATA frame is unwrapped and handed to the normal
//	      transport handler as though it came from the synthetic address.
//
// Everything in between — the Noise handshake, the PSK check, admission
// control, PQ, the tunnel itself — runs unmodified and end-to-end. The relay
// sees ciphertext and byte counts and nothing else.

import (
	"crypto/sha1"
	"encoding/binary"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// PktRelay is the transport type byte for public-relay framing. It sits
// outside the overlay's own range (0x01-0x05, see sessions.go
// isOverlayPacket), so the two protocols sharing this socket demux on one
// byte with no ambiguity. Untyped for gobind (see the file comment).
const PktRelay = 0x10

// Relay sub-types. Wire-identical to client/publicrelay.go.
const (
	relayReserve   = 0x01 // client -> relay: hold a slot for this group
	relayReserveOK = 0x02 // relay -> client: slot held, here is your TTL
	relayDeny      = 0x03 // relay -> client: refused, with a reason
	relayConnect   = 0x04 // client -> relay: pair me with this group
	relayConnectOK = 0x05 // relay -> connector: circuit id
	relayOpen      = 0x06 // relay -> reserver: a circuit opened to you
	relayData      = 0x07 // both ways: [4B circuit][opaque payload]
	relayClose     = 0x08 // both ways: circuit torn down
	relayKeepalive = 0x09 // client -> relay: refresh my reservation
)

// Deny reasons, so a client can tell "this relay is full" (try another) from
// "this relay is out of quota" (stop asking).
const (
	denyDisabled = 1
	denyFull     = 2
	denyQuota    = 3
	denyRate     = 4
	denyNoGroup  = 5
)

const (
	// relayClientReserveEvery refreshes our reservation well inside the
	// relay's 120s TTL, so a single lost keepalive never drops the slot.
	//
	// This is the one timer a phone pays for continuously, so it is worth
	// being explicit: it is a ~60-byte datagram per relay per 45s, which is
	// far below the cost of the keepalives the overlay already sends, and it
	// only runs while the tunnel is up.
	relayClientReserveEvery = 45 * time.Second

	// relayClientMaxRelays bounds how many relays we hold slots on. More than
	// a few is pure overhead: one working relay is enough, and the extras
	// exist only so that a relay going away is not a reconnection event.
	relayClientMaxRelays = 3

	// relayClientDiscoverEvery re-runs relay discovery.
	relayClientDiscoverEvery = 10 * time.Minute
)

// relayDirectoryKey is the directory under which public relays advertise
// themselves. Deliberately PUBLIC and unblinded: the whole point is that a
// node which has not yet reached any peer can still find a relay. Nothing
// sensitive is published — being a public relay is a service announcement and
// the operator opted into it. Must stay byte-identical to the desktop's
// copy in client/publicrelay.go or the two halves look in different places.
func relayDirectoryKey() []byte {
	h := sha1.Sum([]byte("apgo-public-relay-directory-v1"))
	out := make([]byte, 20)
	copy(out, h[:])
	return out
}

type relayCircuitClient struct {
	id      uint32
	relay   *net.UDPAddr
	synth   *net.UDPAddr
	created time.Time
	lastRx  time.Time
}

type relayPeerState struct {
	addr        *net.UDPAddr
	reserved    bool
	lastReserve time.Time
	denied      byte
	deniedAt    time.Time
}

type relayClientState struct {
	enabled atomic.Bool
	conn    *net.UDPConn
	group   [20]byte
	port    int

	mu sync.RWMutex
	// relays we hold (or are seeking) a reservation on.
	relays map[string]*relayPeerState
	// circuits by id and by synthetic address, so both directions are O(1).
	circuits map[uint32]*relayCircuitClient
	bySynth  map[string]*relayCircuitClient

	// observed is the endpoint a relay reported seeing us at — the only
	// reliable way to learn our NAT mapping when STUN is blocked, and on a
	// carrier network that is not rare.
	observed string

	statTx, statRx, statOpened atomic.Uint64

	kp  keypair
	psk []byte
}

var gRelayClient *relayClientState

// synthAddrFor maps a circuit id onto its reserved 240/4 address. The port is
// fixed and meaningless — the id alone identifies the circuit — but must be
// non-zero so nothing downstream treats the address as unresolved.
func synthAddrFor(cid uint32) *net.UDPAddr {
	id := cid & 0x00FFFFFF
	return &net.UDPAddr{
		IP:   net.IPv4(240, byte(id>>16), byte(id>>8), byte(id)),
		Port: 1,
	}
}

// isSyntheticRelayAddr reports whether addr is one of our circuit addresses.
// Called by overlayWriteTo on every send, so it is deliberately
// allocation-free.
func isSyntheticRelayAddr(addr *net.UDPAddr) bool {
	if addr == nil {
		return false
	}
	v4 := addr.IP.To4()
	return v4 != nil && v4[0] == 240
}

// startRelayClient enables outbound use of public relays. group is the
// blinded discovery key of our network: presenting it to a relay is what
// pairs us with our own members and nobody else.
func startRelayClient(conn *net.UDPConn, group []byte, port int, kp keypair, psk []byte) *relayClientState {
	c := &relayClientState{
		conn:     conn,
		port:     port,
		relays:   map[string]*relayPeerState{},
		circuits: map[uint32]*relayCircuitClient{},
		bySynth:  map[string]*relayCircuitClient{},
		kp:       kp,
		psk:      psk,
	}
	copy(c.group[:], group)
	gRelayClient = c
	go c.loop()
	return c
}

func (c *relayClientState) SetEnabled(on bool) {
	was := c.enabled.Swap(on)
	if was && !on {
		c.mu.Lock()
		c.circuits = map[uint32]*relayCircuitClient{}
		c.bySynth = map[string]*relayCircuitClient{}
		c.relays = map[string]*relayPeerState{}
		c.mu.Unlock()
	}
}

func (c *relayClientState) send(relay *net.UDPAddr, sub byte, body []byte) {
	if c.conn == nil {
		return
	}
	buf := make([]byte, 0, 2+len(body))
	buf = append(buf, PktRelay, sub)
	buf = append(buf, body...)
	_, _ = c.conn.WriteToUDP(buf, relay)
}

// AddRelay registers a candidate relay endpoint and immediately tries to
// reserve on it.
func (c *relayClientState) AddRelay(ep string) {
	addr, err := net.ResolveUDPAddr("udp", ep)
	if err != nil || addr == nil || !isValidPeer(ep) {
		return
	}
	c.mu.Lock()
	if _, ok := c.relays[addr.String()]; ok {
		c.mu.Unlock()
		return
	}
	if len(c.relays) >= relayClientMaxRelays {
		c.mu.Unlock()
		return
	}
	c.relays[addr.String()] = &relayPeerState{addr: addr}
	c.mu.Unlock()
	c.send(addr, relayReserve, c.group[:])
}

// handleRelayPacket is the demux entry point for 0x10 frames arriving on the
// shared transport socket.
func handleRelayPacket(pkt []byte, raddr *net.UDPAddr) {
	if len(pkt) < 2 || pkt[0] != PktRelay {
		return
	}
	c := gRelayClient
	if c == nil {
		return
	}
	sub := pkt[1]
	body := pkt[2:]
	if sub == relayData {
		if len(body) < 4 {
			return
		}
		c.deliver(binary.BigEndian.Uint32(body[:4]), body[4:], raddr)
		return
	}
	c.handleClient(sub, body, raddr)
}

// handleClient processes relay control messages addressed to us as a user of
// somebody else's relay.
func (c *relayClientState) handleClient(sub byte, body []byte, raddr *net.UDPAddr) {
	if !c.enabled.Load() {
		return
	}
	switch sub {
	case relayReserveOK:
		c.mu.Lock()
		if st := c.relays[raddr.String()]; st != nil {
			st.reserved = true
			st.lastReserve = time.Now()
		}
		// The relay reports the endpoint it sees us at. On a carrier network
		// this is often the ONLY way we learn our external mapping, because
		// STUN cannot tell us — it reports the mapping toward the STUN
		// server, which on a symmetric NAT is a different mapping entirely.
		if len(body) >= 8 {
			ip := net.IP(append([]byte(nil), body[2:6]...))
			port := int(binary.BigEndian.Uint16(body[6:8]))
			if port > 0 {
				c.observed = net.JoinHostPort(ip.String(), itoaPort(port))
			}
		}
		c.mu.Unlock()
		// Having a slot is only half of it: ask to be paired with anyone else
		// already waiting in our group.
		c.send(raddr, relayConnect, c.group[:])

	case relayDeny:
		if len(body) < 1 {
			return
		}
		c.mu.Lock()
		if st := c.relays[raddr.String()]; st != nil {
			st.denied = body[0]
			st.deniedAt = time.Now()
			st.reserved = false
		}
		c.mu.Unlock()
		// denyNoGroup is not a failure — it means we are the first member
		// here, and our reservation is doing its job: waiting.
		if body[0] != denyNoGroup {
			log.Printf("[relay] %s refused us (reason %d)", raddr, body[0])
		}

	case relayConnectOK, relayOpen:
		if len(body) < 4 {
			return
		}
		c.openCircuit(binary.BigEndian.Uint32(body[:4]), raddr)

	case relayClose:
		if len(body) < 4 {
			return
		}
		c.closeCircuit(binary.BigEndian.Uint32(body[:4]))
	}
}

// openCircuit registers a new circuit and starts a handshake over it. Both
// sides do this; the Noise layer's own initiator/responder resolution settles
// the duplicate, exactly as it does for a simultaneous direct dial.
func (c *relayClientState) openCircuit(cid uint32, relay *net.UDPAddr) {
	synth := synthAddrFor(cid)
	c.mu.Lock()
	if _, exists := c.circuits[cid]; exists {
		c.mu.Unlock()
		return
	}
	cc := &relayCircuitClient{id: cid, relay: relay, synth: synth, created: time.Now(), lastRx: time.Now()}
	c.circuits[cid] = cc
	c.bySynth[synth.String()] = cc
	c.mu.Unlock()
	c.statOpened.Add(1)
	log.Printf("[relay] circuit %d open via %s (peer appears as %s)", cid, relay, synth)

	// Drive the handshake. connectToPeer takes an endpoint string; the
	// synthetic address round-trips through it unchanged, and every send to
	// it is redirected onto the circuit by overlayWriteTo.
	go connectToPeer(synth.String(), c.kp, c.psk)
}

func (c *relayClientState) closeCircuit(cid uint32) {
	c.mu.Lock()
	cc := c.circuits[cid]
	if cc != nil {
		delete(c.circuits, cid)
		delete(c.bySynth, cc.synth.String())
	}
	c.mu.Unlock()
	if cc != nil {
		// Drop the session so the peer is not left listed as reachable
		// through an address that no longer forwards anything.
		if GlobalSessions != nil {
			GlobalSessions.Evict(cc.synth)
		}
		log.Printf("[relay] circuit %d closed", cid)
	}
}

// WriteVia wraps an overlay frame for its circuit and sends it to the relay.
// Returns false when addr is not one of ours, so the caller falls through to
// a normal UDP write.
func (c *relayClientState) WriteVia(addr *net.UDPAddr, frame []byte) bool {
	c.mu.RLock()
	cc := c.bySynth[addr.String()]
	c.mu.RUnlock()
	if cc == nil {
		return false
	}
	out := make([]byte, 0, 6+len(frame))
	out = append(out, PktRelay, relayData)
	var idb [4]byte
	binary.BigEndian.PutUint32(idb[:], cc.id)
	out = append(out, idb[:]...)
	out = append(out, frame...)
	if _, err := c.conn.WriteToUDP(out, cc.relay); err != nil {
		return true // ours, but the write failed; do not fall back to a raw send
	}
	c.statTx.Add(1)
	return true
}

// deliver hands an inbound circuit payload to the normal transport handler,
// attributed to the circuit's synthetic address.
func (c *relayClientState) deliver(cid uint32, payload []byte, from *net.UDPAddr) {
	if !c.enabled.Load() || len(payload) == 0 {
		return
	}
	c.mu.RLock()
	cc := c.circuits[cid]
	c.mu.RUnlock()
	// A payload for an unknown circuit id from a relay we hold a slot on
	// means the relay opened a circuit whose control message we lost. Adopt
	// it rather than dropping traffic for the length of a retry cycle.
	if cc == nil {
		c.mu.RLock()
		known := c.relays[from.String()] != nil
		c.mu.RUnlock()
		if !known {
			return
		}
		c.openCircuit(cid, from)
		c.mu.RLock()
		cc = c.circuits[cid]
		c.mu.RUnlock()
		if cc == nil {
			return
		}
	}
	if cc.relay.String() != from.String() {
		// Circuit ids are only meaningful per-relay; a payload for this id
		// from anywhere else is spoofed.
		return
	}
	c.mu.Lock()
	cc.lastRx = time.Now()
	c.mu.Unlock()
	c.statRx.Add(1)

	if gTransportDeliver != nil {
		// Copy: the caller's buffer is the shared read buffer and is reused
		// as soon as this returns, while the handler may retain slices of it.
		buf := make([]byte, len(payload))
		copy(buf, payload)
		gTransportDeliver(buf, cc.synth)
	}
}

// loop maintains reservations and rediscovers relays.
func (c *relayClientState) loop() {
	resT := time.NewTicker(relayClientReserveEvery)
	discT := time.NewTicker(relayClientDiscoverEvery)
	defer resT.Stop()
	defer discT.Stop()
	c.discover()
	for {
		select {
		case <-resT.C:
			if !c.enabled.Load() {
				continue
			}
			c.mu.RLock()
			var addrs []*net.UDPAddr
			for _, st := range c.relays {
				addrs = append(addrs, st.addr)
			}
			c.mu.RUnlock()
			for _, a := range addrs {
				c.send(a, relayKeepalive, c.group[:])
				// Re-ask for pairing each cycle: a member that joined since
				// our last connect is otherwise invisible to us until one of
				// us restarts.
				c.send(a, relayConnect, c.group[:])
			}
		case <-discT.C:
			c.discover()
		}
	}
}

// discover finds public relays in the tracker directory (relaydirectory.go).
//
// The desktop also queries the DHT; the mobile core has none, which is
// precisely why the tracker directory exists.
func (c *relayClientState) discover() {
	if !c.enabled.Load() {
		return
	}
	// announcePort 0: we are LOOKING for relays, not advertising as one — a
	// phone must never publish itself as a relay.
	for _, ep := range relayDirectoryPeers(currentTrackers(), 0) {
		c.AddRelay(ep)
	}
	c.mu.RLock()
	n := len(c.relays)
	c.mu.RUnlock()
	if n > 0 {
		log.Printf("[relay] holding reservations on %d public relay(s)", n)
	}
}

// ObservedEndpoint returns the address a relay reported seeing us at, or "".
func (c *relayClientState) ObservedEndpoint() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.observed
}

// relayClientStatus is the status-API view of the client half.
type relayClientStatus struct {
	Enabled  bool   `json:"enabled"`
	Relays   int    `json:"relays"`
	Reserved int    `json:"reserved"`
	Circuits int    `json:"circuits"`
	Opened   uint64 `json:"circuits_opened"`
	Sent     uint64 `json:"frames_sent"`
	Received uint64 `json:"frames_received"`
	Observed string `json:"observed_endpoint"`
}

func relayClientStatusSnapshot() relayClientStatus {
	c := gRelayClient
	if c == nil {
		return relayClientStatus{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	reserved := 0
	for _, st := range c.relays {
		if st.reserved {
			reserved++
		}
	}
	return relayClientStatus{
		Enabled:  c.enabled.Load(),
		Relays:   len(c.relays),
		Reserved: reserved,
		Circuits: len(c.circuits),
		Opened:   c.statOpened.Load(),
		Sent:     c.statTx.Load(),
		Received: c.statRx.Load(),
		Observed: c.observed,
	}
}

// gTransportDeliver is set by the transport read loop to its own packet
// handler, so relay-delivered frames take EXACTLY the same path as directly
// received ones — no second implementation to drift out of sync.
var gTransportDeliver func(pkt []byte, raddr *net.UDPAddr)

// overlayWriteTo is the single send point for overlay frames. A synthetic
// 240/4 destination is redirected onto its relay circuit; everything else is
// an ordinary UDP write.
func overlayWriteTo(conn *net.UDPConn, frame []byte, addr *net.UDPAddr) (int, error) {
	if isSyntheticRelayAddr(addr) {
		if c := gRelayClient; c != nil && c.WriteVia(addr, frame) {
			return len(frame), nil
		}
		// A 240/4 address with no live circuit is not routable anywhere.
		// Reporting success would hide a torn-down circuit as silent loss.
		return 0, net.ErrClosed
	}
	return conn.WriteToUDP(frame, addr)
}

// itoaPort avoids pulling strconv in for one call site.
func itoaPort(p int) string {
	if p <= 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for p > 0 {
		i--
		b[i] = byte('0' + p%10)
		p /= 10
	}
	return string(b[i:])
}
