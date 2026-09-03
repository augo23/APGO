package main

// publicrelay.go lets a node volunteer as a PUBLIC relay: a metered, opt-in
// service that carries full overlay traffic for nodes that are not members of
// this node's overlay and never will be.
//
// WHY A SECOND RELAY PATH AT ALL
//
// The existing relay (the 'R' control frame in main.go) forwards for PSK-
// authenticated mesh peers. It cannot be reused here for a reason that is
// structural, not incidental: a stranger has no Noise session with us, because
// establishing one requires the PSK it does not have. So the public tier runs
// OUTSIDE the tunnel, as an opaque circuit switch:
//
//	A ──reserve(group)──▶ R ◀──connect(group)── B
//	A ◀════════ circuit (opaque bytes) ════════▶ B
//
// R pairs two nodes that present the SAME group key and then forwards bytes
// between them without interpreting a single one. The bytes are the ordinary
// overlay transport — Noise handshake, then Noise-encrypted data — so:
//
//   - the relay cannot read the traffic (it holds no keys),
//   - the relay cannot join the overlay (it holds no PSK),
//   - and the relay cannot enumerate networks it carries, because the group
//     key is the PSK-BLINDED DHT key from dht.go, not a network name.
//
// It is, deliberately, closer to a TURN server than to a mix node: it improves
// reachability for symmetric-NAT and CGNAT peers, and claims nothing about
// anonymity. Traffic analysis at the relay is possible and is documented as
// such — an operator sees byte counts and endpoints, never content.
//
// WHY IT IS METERED BY DEFAULT
//
// "Be a public relay" is otherwise an unbounded commitment on someone else's
// broadband bill. Everything here is off unless explicitly enabled, and once
// enabled every transiting byte is charged against the rate limits and the
// period quota in bandwidth.go. When the budget is spent, circuits close and
// new reservations are refused — the node stays a normal overlay member, it
// just stops donating.

import (
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// PktRelay is the transport type byte for public-relay framing. It is outside
// the overlay's own range (0x01-0x05, see sessions.go IsOverlayPacket) and is
// not a bencode dict opener ('d', the DHT), so the three protocols sharing
// this socket demux on one byte with no ambiguity.
const PktRelay byte = 0x10

// Relay sub-types.
const (
	relayReserve   byte = 0x01 // client -> relay: hold a slot for this group
	relayReserveOK byte = 0x02 // relay -> client: slot held, here is your TTL
	relayDeny      byte = 0x03 // relay -> client: refused, with a reason
	relayConnect   byte = 0x04 // client -> relay: pair me with this group
	relayConnectOK byte = 0x05 // relay -> connector: circuit id
	relayOpen      byte = 0x06 // relay -> reserver: a circuit opened to you
	relayData      byte = 0x07 // both ways: [4B circuit][opaque payload]
	relayClose     byte = 0x08 // both ways: circuit torn down
	relayKeepalive byte = 0x09 // client -> relay: refresh my reservation
)

// Deny reasons, reported to the caller so a client can tell "this relay is
// full" (try another) from "this relay is out of quota" (stop asking).
const (
	denyDisabled byte = 1
	denyFull     byte = 2
	denyQuota    byte = 3
	denyRate     byte = 4
	denyNoGroup  byte = 5
)

const (
	relayReservationTTL  = 120 * time.Second
	relayCircuitIdle     = 120 * time.Second
	relayMaxPayload      = 1500
	relayDirectoryTTL    = 15 * time.Minute
	relayAdvertisePeriod = 10 * time.Minute
)

// relayDirectoryKey is the DHT key under which public relays advertise
// themselves. It is deliberately PUBLIC and unblinded: the whole point is that
// a node which has not yet reached any peer can still find a relay. Nothing
// sensitive is published — being a public relay is a service announcement, and
// the operator opted into it.
func relayDirectoryKey() []byte {
	h := sha1.Sum([]byte("apgo-public-relay-directory-v1"))
	out := make([]byte, 20)
	copy(out, h[:])
	return out
}

// ------------------------------------------------------------ server side

type relayReservation struct {
	addr    *net.UDPAddr
	group   [20]byte
	expires time.Time
}

type relayCircuit struct {
	id       uint32
	a, b     *net.UDPAddr
	created  time.Time
	lastSeen time.Time
	bytes    int64
	// perCircuit is this circuit's own share of the allowance, so one busy
	// pair cannot starve every other circuit on the relay.
	perCircuit *tokenBucket
}

// publicRelay is the server half: the node donating capacity.
type publicRelay struct {
	enabled atomic.Bool
	conn    *net.UDPConn
	limits  *bandwidthLimiter

	mu           sync.Mutex
	reservations map[string][]*relayReservation // hex(group) -> reservations
	circuits     map[uint32]*relayCircuit
	perIP        map[string]int // source IP -> live circuits, anti-hog

	maxCircuits      int
	maxPerIP         int
	maxReservations  int
	perCircuitBps    int64
	statCircuits     atomic.Uint64
	statBytes        atomic.Uint64
	statDenied       atomic.Uint64
	statThrottled    atomic.Uint64
	lastAdvertise    time.Time
	advertiseRunning atomic.Bool
}

var gPublicRelay *publicRelay

// startPublicRelay creates the relay in a DISABLED state. Enabling is always
// an explicit act (config, env, or the admin panel), never a default.
func startPublicRelay(conn *net.UDPConn, limits *bandwidthLimiter, maxCircuits, maxPerIP int, perCircuitBps int64) *publicRelay {
	if maxCircuits <= 0 {
		maxCircuits = 64
	}
	if maxPerIP <= 0 {
		maxPerIP = 4
	}
	r := &publicRelay{
		conn:            conn,
		limits:          limits,
		reservations:    map[string][]*relayReservation{},
		circuits:        map[uint32]*relayCircuit{},
		perIP:           map[string]int{},
		maxCircuits:     maxCircuits,
		maxPerIP:        maxPerIP,
		maxReservations: 256,
		perCircuitBps:   perCircuitBps,
	}
	gPublicRelay = r
	go r.janitor()
	return r
}

func (r *publicRelay) send(addr *net.UDPAddr, sub byte, body []byte) {
	if r.conn == nil {
		return
	}
	buf := make([]byte, 0, 2+len(body))
	buf = append(buf, PktRelay, sub)
	buf = append(buf, body...)
	_, _ = r.conn.WriteToUDP(buf, addr)
}

func (r *publicRelay) deny(addr *net.UDPAddr, reason byte) {
	r.statDenied.Add(1)
	r.send(addr, relayDeny, []byte{reason})
}

// handleRelayPacket is the demux entry point for PktRelay datagrams. It serves
// BOTH halves: relay-server messages when we are donating capacity, and
// client-side messages when we are USING somebody else's relay. One type byte,
// two roles, distinguished by sub-type.
func handleRelayPacket(data []byte, raddr *net.UDPAddr) {
	if len(data) < 2 {
		return
	}
	sub := data[1]
	body := data[2:]
	switch sub {
	// --- messages a relay SERVER handles
	case relayReserve, relayConnect, relayKeepalive:
		if r := gPublicRelay; r != nil {
			r.handleServer(sub, body, raddr)
		}
	// --- messages a relay CLIENT handles
	case relayReserveOK, relayDeny, relayConnectOK, relayOpen, relayClose:
		if c := gRelayClient; c != nil {
			c.handleClient(sub, body, raddr)
		}
	// --- data flows in both directions
	case relayData:
		if len(body) < 4 {
			return
		}
		cid := binary.BigEndian.Uint32(body[:4])
		payload := body[4:]
		// A circuit we are SWITCHING (we are the relay) takes priority: the
		// id space is ours, so a match here is authoritative.
		if r := gPublicRelay; r != nil && r.forward(cid, payload, raddr) {
			return
		}
		// Otherwise it is data arriving on a circuit we are USING.
		if c := gRelayClient; c != nil {
			c.deliver(cid, payload, raddr)
		}
	}
}

func (r *publicRelay) handleServer(sub byte, body []byte, raddr *net.UDPAddr) {
	if !r.enabled.Load() {
		r.deny(raddr, denyDisabled)
		return
	}
	if r.limits.QuotaExceeded() {
		r.deny(raddr, denyQuota)
		return
	}
	switch sub {
	case relayReserve, relayKeepalive:
		if len(body) < 20 {
			return
		}
		var g [20]byte
		copy(g[:], body[:20])
		if !r.reserve(g, raddr) {
			r.deny(raddr, denyFull)
			return
		}
		var out [2]byte
		binary.BigEndian.PutUint16(out[:], uint16(relayReservationTTL/time.Second))
		// Echo the observed endpoint back. A node behind NAT usually has no
		// other way to learn the address:port its packets actually arrive
		// from, and that is precisely what it must advertise.
		ep := dhtCompactPeer(raddr)
		r.send(raddr, relayReserveOK, append(out[:], []byte(ep)...))

	case relayConnect:
		if len(body) < 20 {
			return
		}
		var g [20]byte
		copy(g[:], body[:20])
		r.connect(g, raddr)
	}
}

func (r *publicRelay) reserve(group [20]byte, addr *net.UDPAddr) bool {
	key := hex.EncodeToString(group[:])
	r.mu.Lock()
	defer r.mu.Unlock()
	total := 0
	for _, v := range r.reservations {
		total += len(v)
	}
	list := r.reservations[key]
	for _, res := range list {
		if res.addr.String() == addr.String() {
			res.expires = time.Now().Add(relayReservationTTL)
			return true
		}
	}
	if total >= r.maxReservations {
		return false
	}
	r.reservations[key] = append(list, &relayReservation{
		addr: addr, group: group, expires: time.Now().Add(relayReservationTTL),
	})
	return true
}

// connect pairs the caller with every live reservation in the same group,
// opening one circuit each. Pairing is only ever WITHIN a group, so a relay
// can never bridge two unrelated overlays — and since the group key is the
// blinded DHT key, presenting it is itself proof of PSK possession.
func (r *publicRelay) connect(group [20]byte, addr *net.UDPAddr) {
	key := hex.EncodeToString(group[:])
	r.mu.Lock()
	list := r.reservations[key]
	if len(list) == 0 {
		r.mu.Unlock()
		r.deny(addr, denyNoGroup)
		return
	}
	if r.perIP[addr.IP.String()] >= r.maxPerIP || len(r.circuits) >= r.maxCircuits {
		r.mu.Unlock()
		r.deny(addr, denyFull)
		return
	}
	now := time.Now()
	var opened []*relayCircuit
	for _, res := range list {
		if now.After(res.expires) || res.addr.String() == addr.String() {
			continue
		}
		if len(r.circuits) >= r.maxCircuits {
			break
		}
		// Re-check the per-IP cap on EVERY iteration, not once before the
		// loop: a group with N waiting members would otherwise hand one
		// caller N circuits in a single connect, making the cap meaningless
		// precisely when it matters (a large group is the expensive case).
		if r.perIP[addr.IP.String()] >= r.maxPerIP {
			break
		}
		cid := r.newCircuitIDLocked()
		c := &relayCircuit{
			id: cid, a: res.addr, b: addr, created: now, lastSeen: now,
			perCircuit: newTokenBucket(r.perCircuitBps),
		}
		r.circuits[cid] = c
		r.perIP[addr.IP.String()]++
		r.perIP[res.addr.IP.String()]++
		opened = append(opened, c)
	}
	r.mu.Unlock()

	for _, c := range opened {
		var idb [4]byte
		binary.BigEndian.PutUint32(idb[:], c.id)
		// The connector learns the circuit id; the reserver learns the same id
		// plus nothing about who is calling — it will find out from the Noise
		// handshake, or refuse it, which is the correct place for that
		// decision.
		r.send(c.b, relayConnectOK, idb[:])
		r.send(c.a, relayOpen, idb[:])
		r.statCircuits.Add(1)
		r.limits.NoteCircuit()
	}
	if len(opened) == 0 {
		r.deny(addr, denyNoGroup)
	}
}

func (r *publicRelay) newCircuitIDLocked() uint32 {
	for {
		var b [4]byte
		_, _ = io.ReadFull(crand.Reader, b[:])
		// Keep ids inside 24 bits: the client side encodes the circuit id in a
		// synthetic 240.0.0.0/4 address (see relayclient), which has exactly
		// 24 bits of host space.
		id := binary.BigEndian.Uint32(b[:]) & 0x00FFFFFF
		if id == 0 {
			continue
		}
		if _, taken := r.circuits[id]; !taken {
			return id
		}
	}
}

// forward moves one datagram across a circuit, charging it against every
// limit. Returns true when the circuit was ours (so the caller stops looking).
func (r *publicRelay) forward(cid uint32, payload []byte, from *net.UDPAddr) bool {
	if len(payload) == 0 || len(payload) > relayMaxPayload {
		return false
	}
	r.mu.Lock()
	c := r.circuits[cid]
	if c == nil {
		r.mu.Unlock()
		return false
	}
	var dst *net.UDPAddr
	switch from.String() {
	case c.a.String():
		dst = c.b
	case c.b.String():
		dst = c.a
	default:
		// A third party guessing a circuit id. Not ours to forward.
		r.mu.Unlock()
		return false
	}
	c.lastSeen = time.Now()
	c.bytes += int64(len(payload))
	r.mu.Unlock()

	if !r.enabled.Load() {
		r.closeCircuit(cid, denyDisabled)
		return true
	}
	// Charge BOTH directions: the bytes arrived on our downlink and leave on
	// our uplink, and an operator who capped upload at 1 MB/s did not agree to
	// also absorb 1 MB/s of download.
	n := len(payload)
	if !c.perCircuit.Allow(n) {
		r.statThrottled.Add(1)
		return true // dropped: over this circuit's share
	}
	if !r.limits.AllowDown(n) || !r.limits.AllowUp(n) {
		r.statThrottled.Add(1)
		if r.limits.QuotaExceeded() {
			r.closeCircuit(cid, denyQuota)
		}
		return true
	}
	r.statBytes.Add(uint64(n))

	out := make([]byte, 0, 6+len(payload))
	out = append(out, PktRelay, relayData)
	var idb [4]byte
	binary.BigEndian.PutUint32(idb[:], cid)
	out = append(out, idb[:]...)
	out = append(out, payload...)
	_, _ = r.conn.WriteToUDP(out, dst)
	return true
}

func (r *publicRelay) closeCircuit(cid uint32, reason byte) {
	r.mu.Lock()
	c := r.circuits[cid]
	if c == nil {
		r.mu.Unlock()
		return
	}
	delete(r.circuits, cid)
	if n := r.perIP[c.a.IP.String()]; n > 0 {
		r.perIP[c.a.IP.String()] = n - 1
	}
	if n := r.perIP[c.b.IP.String()]; n > 0 {
		r.perIP[c.b.IP.String()] = n - 1
	}
	r.mu.Unlock()

	var idb [4]byte
	binary.BigEndian.PutUint32(idb[:], cid)
	body := append(idb[:], reason)
	r.send(c.a, relayClose, body)
	r.send(c.b, relayClose, body)
}

// janitor expires reservations and idle circuits. Without it a relay leaks a
// slot for every peer that vanishes mid-circuit — which on a public service is
// most of them.
func (r *publicRelay) janitor() {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		var stale []uint32
		r.mu.Lock()
		for k, list := range r.reservations {
			kept := list[:0]
			for _, res := range list {
				if now.Before(res.expires) {
					kept = append(kept, res)
				}
			}
			if len(kept) == 0 {
				delete(r.reservations, k)
			} else {
				r.reservations[k] = kept
			}
		}
		for id, c := range r.circuits {
			if now.Sub(c.lastSeen) > relayCircuitIdle {
				stale = append(stale, id)
			}
		}
		r.mu.Unlock()
		for _, id := range stale {
			r.closeCircuit(id, denyRate)
		}
	}
}

// Advertise publishes this relay in the public DHT directory so strangers can
// find it. Only ever called while the relay is enabled AND has quota left: a
// relay that advertises while refusing every connection is worse than one that
// stays quiet, because clients keep choosing it over working relays.
func (r *publicRelay) Advertise(port int) {
	if !r.enabled.Load() || r.limits.QuotaExceeded() || gDHT == nil {
		return
	}
	if !r.advertiseRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer r.advertiseRunning.Store(false)
		gDHT.lookupPeers(relayDirectoryKey(), port)
		r.mu.Lock()
		r.lastAdvertise = time.Now()
		r.mu.Unlock()
	}()
}

// SetEnabled turns the public tier on or off at runtime. Turning it OFF closes
// every live circuit immediately rather than letting them drain: an operator
// who hit "stop sharing" means now, usually because something on their link
// needs the bandwidth back.
func (r *publicRelay) SetEnabled(on bool) {
	was := r.enabled.Swap(on)
	if was && !on {
		r.mu.Lock()
		ids := make([]uint32, 0, len(r.circuits))
		for id := range r.circuits {
			ids = append(ids, id)
		}
		r.reservations = map[string][]*relayReservation{}
		r.mu.Unlock()
		for _, id := range ids {
			r.closeCircuit(id, denyDisabled)
		}
		log.Printf("[relay] public relay disabled; closed %d circuit(s)", len(ids))
	} else if !was && on {
		log.Printf("[relay] public relay ENABLED: up=%s down=%s quota=%s",
			formatRate(r.limits.up.Rate()), formatRate(r.limits.down.Rate()),
			formatRate(r.limits.Status().QuotaBytes))
	}
}

// publicRelayStatus is the dashboard view.
type publicRelayStatus struct {
	Enabled       bool            `json:"enabled"`
	Circuits      int             `json:"circuits_open"`
	Reservations  int             `json:"reservations"`
	MaxCircuits   int             `json:"max_circuits"`
	CircuitsTotal uint64          `json:"circuits_total"`
	BytesRelayed  uint64          `json:"bytes_relayed"`
	Denied        uint64          `json:"denied"`
	Throttled     uint64          `json:"throttled"`
	Bandwidth     bandwidthStatus `json:"bandwidth"`
}

func publicRelayStatusSnapshot() publicRelayStatus {
	r := gPublicRelay
	if r == nil {
		return publicRelayStatus{}
	}
	r.mu.Lock()
	circuits := len(r.circuits)
	res := 0
	for _, v := range r.reservations {
		res += len(v)
	}
	r.mu.Unlock()
	return publicRelayStatus{
		Enabled:       r.enabled.Load(),
		Circuits:      circuits,
		Reservations:  res,
		MaxCircuits:   r.maxCircuits,
		CircuitsTotal: r.statCircuits.Load(),
		BytesRelayed:  r.statBytes.Load(),
		Denied:        r.statDenied.Load(),
		Throttled:     r.statThrottled.Load(),
		Bandwidth:     r.limits.Status(),
	}
}
