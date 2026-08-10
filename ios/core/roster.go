package overlaymobile

// roster.go maintains a gossip'd directory of the nodes in this overlay
// network, so the peer list can show EVERY member — including nodes this
// device can only reach through a relay — without depending on data traffic
// having taught the routing table a path. Relay-route rows (ip_learning) come
// and go with the routing table's memory, which made relay-only peers flicker
// in and out of the list; the roster keeps them steadily visible.
//
//	OVLYCTL1 T <json>   — "these nodes exist": [{"ip":..,"name":..,"fp":..},…]
//
// Each node advertises ITSELF and its DIRECT (established) peers on the
// keepalive tick. Entries refresh their last-seen time on every arrival and
// expire quietly after rosterTTL, so a node that leaves the network drops out
// of everyone's list within a couple of minutes. Advertisements are one-hop
// facts and are NOT re-gossiped, so a stale entry can never circulate — and
// one hop converges for the common mesh shape, where every always-on node
// holds a direct session to the rest.

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"sync"
	"time"
)

const (
	rosterTTL        = 2 * time.Minute
	rosterMaxEntries = 64
	rosterMaxName    = 64
	// rosterMaxFrameBytes bounds the marshalled JSON so the control frame fits
	// in a single un-fragmented datagram once the transport's own overhead
	// (Noise header + AEAD tag, and the PQ wrapper when engaged) is added on
	// top. Conservative on purpose: a roster that is dropped for being too
	// large is worse than one that carries a few fewer entries per tick.
	rosterMaxFrameBytes = 1350
)

type rosterEntry struct {
	IP   string `json:"ip"`
	Name string `json:"name,omitempty"`
	FP   string `json:"fp,omitempty"`
	// PK is the node's full base64 static public key. FP alone is a truncated
	// fingerprint — enough to LABEL a row, useless for acting on it: both
	// revocation records and admin provisions are addressed to the full key.
	// Without PK a relay-only node could be listed but never renamed, revoked
	// or approved, because the admin UI had nothing to send.
	//
	// Not a secret: a static public key is exchanged in the clear during any
	// Noise handshake, and this frame already travels inside an authenticated,
	// encrypted session with a network member.
	PK string `json:"pk,omitempty"`
	// PQ is the node's live post-quantum state, carried in the gossip so a
	// device that only reaches this node through a relay can still display
	// it truthfully (per-session PQ status frames only flow over DIRECT
	// sessions, so relayed rows used to show PQ off even when the node had
	// it on for every hop).
	PQ bool `json:"pq,omitempty"`
	// Exit: the node can be an internet exit for the VPN relay. Same rationale
	// as PQ: 'E' announces only flow over DIRECT sessions, so a device that
	// reaches the exit through a relay showed no green E for it — on small
	// meshes (a phone + a NATed exit) that hid the ONLY exit that existed.
	Exit bool `json:"exit,omitempty"`
	// ExitErr: the node WANTED to be an exit but its NAT setup failed, so it
	// refuses to advertise. Carried in the gossip so every OTHER dashboard
	// can badge it — without this, the answer to "why is there no E for that
	// node" lived exclusively in the failing node's own log/panel.
	ExitErr bool `json:"exit_err,omitempty"`
	// V6: the node has a globally routable IPv6 transport address. Gossiped
	// so any dashboard can answer "would IPv6 fix this relayed pair?" using
	// facts about BOTH ends. Must stay in sync with client/roster.go — the
	// two cores exchange these frames with each other.
	V6 bool `json:"v6,omitempty"`
}

// rosterView is one live roster entry plus when we last heard it advertised.
type rosterView struct {
	rosterEntry
	Seen time.Time
}

var (
	rosterMu    sync.Mutex
	rosterNodes = map[string]rosterView{}
)

// buildRosterFrame returns an OVLYCTL1 'T' frame advertising this node and
// its established direct peers, or nil when there is nothing to say.
func buildRosterFrame() []byte {
	var entries []rosterEntry
	seen := map[string]bool{}
	if myOverlayIP != "" {
		entries = append(entries, rosterEntry{
			IP: myOverlayIP, Name: getMyFriendlyName(), FP: peerKeyFingerprint(gKP.pub[:]),
			PK:      base64.StdEncoding.EncodeToString(gKP.pub[:]),
			PQ:      pqEnabled,
			Exit:    amExit,
			ExitErr: exitNATErr != "",
			V6:      hasGlobalIPv6(),
		})
		seen[myOverlayIP] = true
	}
	for _, addr := range GlobalSessions.EstablishedAddrs() {
		s := GlobalSessions.GetByAddr(addr)
		if s == nil || !s.Established() {
			continue
		}
		ip := peerOverlayIPByPub(s.peerStatic)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		peerIsExit, _ := exitStatusFor(s.peerStatic)
		// Carry the peer's OWN gossiped flags forward, or they only survive
		// one hop and every node further away sees false (a v6-capable node
		// shown as "no v6" to anyone reaching it via relay).
		var peerV6, peerExitErr bool
		if rv, ok := rosterLookup(ip); ok {
			peerV6, peerExitErr = rv.V6, rv.ExitErr
			peerIsExit = peerIsExit || rv.Exit
		}
		entries = append(entries, rosterEntry{
			IP: ip, Name: resolvePeerName(s.peerStatic), FP: peerKeyFingerprint(s.peerStatic[:]),
			PK:      base64.StdEncoding.EncodeToString(s.peerStatic[:]),
			PQ:      peerPQByPub(s.peerStatic),
			Exit:    peerIsExit,
			ExitErr: peerExitErr,
			V6:      peerV6,
		})
		if len(entries) >= rosterMaxEntries {
			break
		}
	}
	if len(entries) == 0 {
		return nil
	}
	b, err := json.Marshal(entries)
	if err != nil {
		return nil
	}
	// Keep the frame inside one un-fragmented datagram. rosterMaxEntries alone
	// never bounded the BYTES, and adding the full public key roughly doubles
	// the per-entry cost. An oversized UDP datagram fragments at the IP layer,
	// and fragments are dropped outright by plenty of NATs and middleboxes — so
	// the roster would stop arriving, silently, on the paths that need it most.
	// Trimmed entries are re-advertised on the next keepalive tick.
	for len(b) > rosterMaxFrameBytes && len(entries) > 1 {
		n := len(entries) * rosterMaxFrameBytes / len(b)
		if n >= len(entries) {
			n = len(entries) - 1
		}
		if n < 1 {
			n = 1
		}
		entries = entries[:n]
		if b, err = json.Marshal(entries); err != nil {
			return nil
		}
	}
	out := append([]byte(nil), ctlMagic...)
	out = append(out, 'T')
	return append(out, b...)
}

// handleRoster merges a received roster advertisement. It arrives over an
// authenticated, encrypted session from a network member — the same trust
// level as PEX. Bounded and validated; an empty name/fp never overwrites a
// known one (peers that haven't resolved a name yet shouldn't blank ours).
func handleRoster(payload []byte) {
	var entries []rosterEntry
	if json.Unmarshal(payload, &entries) != nil {
		return
	}
	now := time.Now()
	sawNew := false
	rosterMu.Lock()
	for i, e := range entries {
		if i >= rosterMaxEntries {
			break
		}
		if e.IP == "" || e.IP == myOverlayIP || net.ParseIP(e.IP) == nil {
			continue
		}
		if len(e.Name) > rosterMaxName {
			e.Name = e.Name[:rosterMaxName]
		}
		// Drop anything that isn't a well-formed 32-byte X25519 key rather than
		// storing it: everything downstream feeds it into an API that expects
		// exactly that.
		if e.PK != "" {
			if raw, err := base64.StdEncoding.DecodeString(e.PK); err != nil || len(raw) != 32 {
				e.PK = ""
			}
		}
		if cur, ok := rosterNodes[e.IP]; ok {
			if e.Name == "" {
				e.Name = cur.Name
			}
			if e.FP == "" {
				e.FP = cur.FP
			}
			// Never let a peer running an older build (which sends no pk) blank
			// a key we already learned.
			if e.PK == "" {
				e.PK = cur.PK
			}
			// CAPABILITY FLAGS ARE STICKY (true wins).
			//
			// These arrive from two kinds of sender: the node ITSELF (which
			// knows the truth) and third parties relaying what they know
			// (which may be stale, or an older build that sends nothing at
			// all). Letting a second-hand `false` overwrite a known `true`
			// makes the flags flicker with whichever neighbour gossiped last
			// — a v6-capable node would blink between "v6" and "no v6" as
			// different rosters arrived. Entries expire on rosterTTL, so a
			// capability that genuinely goes away still clears within a
			// couple of minutes.
			e.PQ = e.PQ || cur.PQ
			e.Exit = e.Exit || cur.Exit
			e.ExitErr = e.ExitErr || cur.ExitErr
			e.V6 = e.V6 || cur.V6
		} else {
			sawNew = true
		}
		rosterNodes[e.IP] = rosterView{rosterEntry: e, Seen: now}
	}
	rosterMu.Unlock()
	// A node we didn't know about: try to upgrade it to a direct session RIGHT
	// NOW instead of waiting for the next keepalive tick. This is what makes a
	// freshly-joined device converge on the whole network in ~one round-trip:
	// first session → roster arrives → punch signaling goes out immediately.
	// shouldTryConnect still caps attempts per node, so a burst of roster
	// frames can't spam punches.
	if sawNew {
		go connectRosterNodes()
	}
}

// connectRosterNodes fires coordinated-connect signaling at every roster node
// we have no direct established session to. The roster makes such nodes
// VISIBLE; this makes them DIRECT: the 'C' frame is relayed to the target,
// which punches back at our candidate endpoints (including our LAN address),
// so two devices on the same Wi-Fi — or two containers on the same host —
// upgrade from a relayed row to a direct session within seconds instead of
// waiting for user traffic or the same-site hairpin ladder. shouldTryConnect
// caps this at one attempt per node per 15s (shared with the data-path
// trigger), so an unreachable node costs a few tiny frames a minute.
func connectRosterNodes() {
	cands := myConnectCandidates()
	if cands == "" || myOverlayIP == "" {
		return
	}
	direct := map[string]bool{}
	for _, addr := range GlobalSessions.EstablishedAddrs() {
		s := GlobalSessions.GetByAddr(addr)
		if s == nil || !s.Established() {
			continue
		}
		if ip := peerOverlayIPByPub(s.peerStatic); ip != "" {
			direct[ip] = true
		}
	}
	for _, e := range rosterSnapshot() {
		if e.IP == myOverlayIP || direct[e.IP] || isOverlayIPRevoked(e.IP) {
			continue
		}
		if !shouldTryConnect(e.IP) {
			continue
		}
		sendControlToward(e.IP, buildConnectFrame('C', e.IP, myOverlayIP, cands))
	}
}

// sendRosterTo shares the node directory with a single peer immediately —
// used right after a peer announces itself, so a newly-joined device learns
// the whole network within one round-trip of its FIRST session instead of
// waiting out the next keepalive tick. Paired with the instant punch in
// handleRoster, a phone joining Wi-Fi reaches every reachable node in a
// couple of seconds.
func sendRosterTo(raddr *net.UDPAddr) {
	frame := buildRosterFrame()
	if frame == nil || GlobalConn == nil {
		return
	}
	if s := GlobalSessions.GetByAddr(raddr); s != nil && s.Established() {
		_ = sendPacket(GlobalConn, raddr, s, frame)
	}
}

// rosterLookup returns the fresh roster entry for an overlay IP, if any.
func rosterLookup(ip string) (rosterView, bool) {
	rosterMu.Lock()
	defer rosterMu.Unlock()
	n, ok := rosterNodes[ip]
	if !ok || time.Since(n.Seen) > rosterTTL {
		return rosterView{}, false
	}
	return n, true
}

// rosterSnapshot returns the live (unexpired) roster entries, pruning the rest.
func rosterSnapshot() []rosterView {
	now := time.Now()
	rosterMu.Lock()
	defer rosterMu.Unlock()
	out := make([]rosterView, 0, len(rosterNodes))
	for ip, n := range rosterNodes {
		if now.Sub(n.Seen) > rosterTTL {
			delete(rosterNodes, ip)
			continue
		}
		out = append(out, n)
	}
	return out
}
