package main

import (
	"net"
	"sync"
	"time"
)

type IPLearning struct {
	mu sync.RWMutex
	m  map[string]*entry
}

type entry struct {
	addr *net.UDPAddr
	seen time.Time
}

const ipLearnEvictInterval = 5 * time.Minute
const ipLearnStaleTimeout = 5 * time.Minute

func NewIPLearningTable() *IPLearning {
	t := &IPLearning{m: map[string]*entry{}}
	go t.evictLoop()
	return t
}

func (t *IPLearning) evictLoop() {
	ticker := time.NewTicker(ipLearnEvictInterval)
	defer ticker.Stop()
	for range ticker.C {
		t.mu.Lock()
		now := time.Now()
		for ip, e := range t.m {
			if now.Sub(e.seen) > ipLearnStaleTimeout {
				delete(t.m, ip)
			}
		}
		t.mu.Unlock()
	}
}


// sameUDPAddr compares two endpoints without building their string forms.
// UDPAddr.String() allocates, and the comparison it was used for sits on the
// per-packet receive path.
func sameUDPAddr(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Port == b.Port && a.Zone == b.Zone && a.IP.Equal(b.IP)
}

func (t *IPLearning) Learn(ip string, addr *net.UDPAddr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.m[ip]; ok {
		// STEADY STATE, and it is the overwhelming majority of calls: this
		// runs on EVERY received data packet, and the route almost always
		// matches the one already recorded. Refresh in place and return.
		//
		// The previous shape fell through to the allocation below even when
		// nothing had changed, and reached it via two UDPAddr.String() calls
		// — so every packet a phone received cost three allocations and two
		// string builds inside a global mutex. sameUDPAddr compares the
		// fields directly and allocates nothing.
		if sameUDPAddr(e.addr, addr) {
			e.seen = time.Now()
			return
		}
		// ROUTE-CLASS PREFERENCE. Routes to an overlay IP come in classes:
		//
		//   direct — a session whose peer key OWNS ip (it is the device itself)
		//   relay  — a session to some OTHER peer that forwarded ip's traffic
		//
		// and within a class a route is proven LIVE (RouteIsLive: decrypted
		// inbound within ~2 keepalives) or merely established. The rules:
		//
		//   1. A LIVE direct route is never displaced by a relay. Since
		//      unproven senders flood relay-wrapped duplicates in parallel
		//      with the direct copy (see the TUN egress path), a relayed
		//      duplicate arriving is EXPECTED noise — letting it steal the
		//      route sent return traffic through the relay, starved the
		//      direct session into staleness on both ends, and cascaded
		//      node after node into relay mode (observed fleet-wide within
		//      minutes of the parallel-flood change: "everything is relayed
		//      now"). Direct-and-live always wins.
		//   2. A DEAD direct route never blocks failover. If the direct
		//      session has nothing decrypted inbound for routeLiveTimeout,
		//      any working route — a relay included — may take over
		//      immediately, instead of blackholing until the 45s stale
		//      sweep. This is the same established-vs-live distinction as
		//      RouteIsLive's own doc comment.
		//   3. An established direct route always beats a relay route
		//      (relay -> direct upgrade, as before).
		//   4. Between two routes to the SAME peer key (its LAN + WAN
		//      addresses), keep the incumbent while it is live — sticky, no
		//      flip-flopping — but prefer an upgrade to the LAN path, and
		//      fail over when the incumbent is dead and the candidate live.
		//   5. Between two relay routes, last-writer-wins (as before): the
		//      most recent forwarder is the one proven to reach us.
		if GlobalSessions != nil {
			cur := GlobalSessions.GetByAddr(e.addr)
			cand := GlobalSessions.GetByAddr(addr)
			if cur.Established() {
				if cand.Established() && cur.peerStatic == cand.peerStatic {
					// Rule 4: two routes to the same device.
					if isPrivateUDPAddr(addr) && !isPrivateUDPAddr(e.addr) {
						e.addr = addr
						e.seen = time.Now()
						return
					}
					if GlobalSessions.RouteIsLive(e.addr) || !GlobalSessions.RouteIsLive(addr) {
						e.seen = time.Now()
						return
					}
					// Incumbent dead, candidate live: fall through, take it.
				} else if peerOverlayIPByPub(cur.peerStatic) == ip {
					// Incumbent is the DIRECT route to ip; candidate is a
					// relay or an unknown endpoint.
					candDirect := cand.Established() && peerOverlayIPByPub(cand.peerStatic) == ip
					if !candDirect && GlobalSessions.RouteIsLive(e.addr) {
						return // rule 1: live direct route is never stolen
					}
					// Rule 2/3: dead direct route, or candidate is itself
					// direct — fall through, take the candidate.
				}
				// Incumbent is a relay: rules 3 and 5 — overwrite.
			}
		}
	}
	t.m[ip] = &entry{addr: addr, seen: time.Now()}
}

// ForgetAddr removes every overlay-IP mapping that points at addr. Called
// when a session to addr is evicted or when a send-path lookup discovers the
// mapping is stale — routing to an endpoint with no live session silently
// blackholes traffic even after a fresh session exists elsewhere.
func (t *IPLearning) ForgetAddr(addr *net.UDPAddr) {
	key := addr.String()
	t.mu.Lock()
	defer t.mu.Unlock()
	for ip, e := range t.m {
		if e.addr.String() == key {
			delete(t.m, ip)
		}
	}
}

// OverlayIPFor returns the overlay IP currently mapped to addr, or "" if none
// is known — or if the mapping is AMBIGUOUS. It is the reverse of Lookup, used
// by the admin control server to label each session with its overlay address.
// With relayed routes, MANY overlay IPs legitimately map to one next-hop
// endpoint (the relay's); returning a random one of them (Go map order)
// mislabeled the relay's own row with a relayed peer's address on some polls
// and not others — the peer list flickered between right and wrong. Only an
// unambiguous single mapping is trustworthy as "this endpoint's own address".
func (t *IPLearning) OverlayIPFor(addr *net.UDPAddr) string {
	if addr == nil {
		return ""
	}
	key := addr.String()
	t.mu.RLock()
	defer t.mu.RUnlock()
	found := ""
	for ip, e := range t.m {
		if e.addr.String() == key {
			if found != "" {
				return "" // several IPs route here — can't tell which is its own
			}
			found = ip
		}
	}
	return found
}

// RemapAddr repoints every overlay-IP mapping from old to new. Used when a peer
// roams to a new endpoint so routing follows it without waiting to re-learn.
func (t *IPLearning) RemapAddr(old, newAddr *net.UDPAddr) {
	if old == nil || newAddr == nil {
		return
	}
	key := old.String()
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, e := range t.m {
		if e.addr.String() == key {
			e.addr = newAddr
			e.seen = time.Now()
		}
	}
}

func (t *IPLearning) Lookup(ip string) *net.UDPAddr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if e, ok := t.m[ip]; ok {
		return e.addr
	}
	return nil
}

// LearnedIP is one entry of the routing table: an overlay IP, the endpoint it
// currently routes to (a direct peer OR a relay next-hop), and when it was last
// refreshed.
type LearnedIP struct {
	IP   string
	Addr *net.UDPAddr
	Seen time.Time
}

// Entries returns a snapshot of the learned overlay-IP routes. The peer list
// uses it to surface RELAY-only peers (an overlay IP whose next hop is another
// peer's endpoint) that have no direct session and would otherwise be invisible
// even though traffic to them works.
func (t *IPLearning) Entries() []LearnedIP {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]LearnedIP, 0, len(t.m))
	for ip, e := range t.m {
		out = append(out, LearnedIP{IP: ip, Addr: e.addr, Seen: e.seen})
	}
	return out
}
