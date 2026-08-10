package overlaymobile

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

func (t *IPLearning) Learn(ip string, addr *net.UDPAddr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.m[ip]; ok && e.addr.String() != addr.String() {
		// Sticky routing between DUPLICATE sessions. LAN discovery + tracker
		// announce can legitimately produce two established sessions to the
		// SAME peer (its LAN address and its WAN/hairpin address). Both send
		// keepalives, so last-writer-wins here made the route to that peer
		// flip between the two paths every few seconds — and when one path
		// is one-way (typical router hairpin), traffic blackholed in bursts,
		// recovering only briefly each time the good path's keepalive landed.
		// If the incumbent mapping and the new candidate are both live
		// sessions to the same peer key, keep the incumbent. When it truly
		// dies it is evicted (and ForgetAddr'd) within the stale timeout,
		// and the other path takes over. Mappings via DIFFERENT peers (e.g.
		// relay -> direct upgrades) still overwrite as before.
		if GlobalSessions != nil {
			cur := GlobalSessions.GetByAddr(e.addr)
			cand := GlobalSessions.GetByAddr(addr)
			if cur.Established() && cand.Established() && cur.peerStatic == cand.peerStatic {
				// Exception: upgrade to the peer's LAN route. Among two live
				// routes to the same device, a directly-attached (private)
				// path always beats a WAN/hairpin path.
				if isPrivateUDPAddr(addr) && !isPrivateUDPAddr(e.addr) {
					e.addr = addr
					e.seen = time.Now()
					return
				}
				e.seen = time.Now()
				return
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
