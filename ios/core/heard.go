package overlaymobile

// heard.go — "this node is talking to us through the mesh right now" memory.
//
// THE HOLE THIS FILLS
//
// A relay-only node that has no direct sessions of its OWN is invisible to the
// peer list in two independent ways at once:
//
//   1. roster.go advertises a node and its DIRECT (established) peers, one hop,
//      and never re-gossips. A node holding zero direct sessions is therefore
//      advertised by nobody and never enters anyone's roster.
//   2. ip_learning only holds a route while data traffic is actively flowing
//      (ipLearnStaleTimeout, 5 min), so its row appears while you are loading a
//      page from the node and is forgotten shortly after.
//
// Fall into both at once — which is exactly what happens to a node behind a
// symmetric NAT that can dial out but never be dialled — and the node is fully
// reachable through the relay flood while showing up NOWHERE in the UI. Pings
// work, pages load, and the list says the node does not exist.
//
// THE SIGNAL USED HERE
//
// Such a node is not silent. It is pushing connect requests/acks through the
// mesh continuously, trying to establish the direct session it can't get:
//
//   [connect] punch-request from 10.22.22.22 (candidates: …); punching + acking
//
// Every one of those frames reaching us is proof of two things at once — the
// node is alive, and a relay path to it exists at this moment. That is
// precisely the "can I see a route to it" question the peer list wants
// answered, and it is available even when both sources above are empty.
//
// Mirrored from client/heard.go — keep the two in sync.
//
// This table records the source overlay IP of those relayed frames and gives
// control.go a third, independent source of relayed rows. It never creates a
// route or influences forwarding — it only affects what the UI can see.

import (
	"net"
	"sync"
	"time"
)

const (
	// Longer than ipLearnStaleTimeout (5 min) on purpose: this table exists to
	// stop relay-only rows flickering out between bursts of traffic, so its
	// memory has to outlast the routing table's. Still short enough that a node
	// which genuinely leaves drops off the list in minutes.
	heardTTL = 10 * time.Minute
	// Bounded so a hostile or broken peer cannot grow this map without limit by
	// spraying connect frames with forged source IPs. Eviction is oldest-first.
	heardMaxEntries = 128
)

type heardEntry struct {
	// Via is the neighbour that handed us the frame — its overlay IP when we
	// know it, else its UDP endpoint. Shown in the "relayed via" column.
	Via  string
	Seen time.Time
}

var (
	heardMu sync.Mutex
	heardM  = map[string]heardEntry{}
)

// noteHeardFrom records that a relayed control frame from overlay IP `ip`
// reached us via neighbour `via`. Safe to call on every frame; it is a map
// write on a short-lived lock and nothing else.
func noteHeardFrom(ip, via string) {
	if ip == "" || net.ParseIP(ip) == nil || ip == myOverlayIP {
		return
	}
	heardMu.Lock()
	defer heardMu.Unlock()
	if _, exists := heardM[ip]; !exists && len(heardM) >= heardMaxEntries {
		var oldestIP string
		var oldest time.Time
		for k, v := range heardM {
			if oldestIP == "" || v.Seen.Before(oldest) {
				oldestIP, oldest = k, v.Seen
			}
		}
		delete(heardM, oldestIP)
	}
	heardM[ip] = heardEntry{Via: via, Seen: time.Now()}
}

// heardSnapshot returns the live entries, expiring stale ones as it goes.
// Expiry happens here rather than on a ticker because the only reader is the
// peer list, which is polled by the UI — no goroutine needed.
func heardSnapshot() map[string]heardEntry {
	heardMu.Lock()
	defer heardMu.Unlock()
	now := time.Now()
	out := make(map[string]heardEntry, len(heardM))
	for ip, e := range heardM {
		if now.Sub(e.Seen) > heardTTL {
			delete(heardM, ip)
			continue
		}
		out[ip] = e
	}
	return out
}

// relayViaLabel names the neighbour a relayed frame arrived through: its
// overlay IP when it has announced one, else its raw UDP endpoint. Matches how
// the ip_learning relay rows in control.go label their Via field, so the two
// row sources read identically in the UI.
func relayViaLabel(raddr *net.UDPAddr) string {
	if raddr == nil {
		return ""
	}
	if s := GlobalSessions.GetByAddr(raddr); s.Established() {
		if ip := peerOverlayIPByPub(s.peerStatic); ip != "" {
			return ip
		}
	}
	return raddr.String()
}
