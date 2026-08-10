package main

// control.go implements a small local admin API served over a unix-domain
// socket on a shared volume. The separate overlay-admin container connects to
// it to list live sessions and revoke (kick) a peer. Nothing here is exposed
// on the network — access is gated by filesystem permissions on the socket.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// overlayCIDR is this node's overlay subnet (e.g. "10.22.55.0/24"), set in
// main(). The control server uses it to derive a peer's stable overlay IP from
// that peer's static public key when no announced mapping is known yet.
var overlayCIDR string

// gNetworkName / gPSKString / gRendezvous hold the join details (set in main())
// so the admin panel can build a "join QR" over the local control socket. The
// PSK is only exposed on the localhost/unix control socket, gated by the admin
// login on the dashboard side.
var (
	gNetworkName string
	gPSKString   string
	gRendezvous  []string
	// gCipherName is the canonical transport-cipher name ("chacha"/"aesgcm"),
	// included in join info so a scanned QR configures matching crypto — a
	// cipher mismatch fails every handshake with only a silent MAC error.
	gCipherName string
)

// nodeStartTime marks process start, for uptime reporting.
var nodeStartTime = time.Now()

// --- revocation list ------------------------------------------------------

const defaultRevocationTTL = 30 * time.Minute

// revocationList holds peer static public keys an operator has kicked via the
// admin dashboard. Entries expire after ttl, so a revoke is a temporary ban (a
// live "kick"), not permanent membership removal. In-memory only: it resets on
// restart. Permanent, cryptographic membership control is the separate
// authorized-keys feature.
type revocationList struct {
	mu  sync.Mutex
	m   map[[32]byte]time.Time
	ttl time.Duration
}

func newRevocationList(ttl time.Duration) *revocationList {
	return &revocationList{m: map[[32]byte]time.Time{}, ttl: ttl}
}

func (r *revocationList) revoke(pub [32]byte) {
	if pub == ([32]byte{}) {
		return
	}
	r.mu.Lock()
	r.m[pub] = time.Now().Add(r.ttl)
	r.mu.Unlock()
}

func (r *revocationList) isRevoked(pub [32]byte) bool {
	if pub == ([32]byte{}) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	exp, ok := r.m[pub]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(r.m, pub)
		return false
	}
	return true
}

func revocationTTLFromEnv() time.Duration {
	if v := os.Getenv("REVOCATION_TTL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return defaultRevocationTTL
}

var revoked = newRevocationList(revocationTTLFromEnv())

// --- session listing / revocation ----------------------------------------

// SessionInfo is the JSON view of one live session, served to the admin UI.
type SessionInfo struct {
	Remote       string `json:"remote"`     // peer UDP endpoint (ip:port) — stable table key
	OverlayIP    string `json:"overlay_ip"` // announced or key-derived overlay address
	Name         string `json:"name"`       // friendly name the peer advertises, if any
	KeyFP        string `json:"key_fp"`     // short fingerprint of the peer static key
	PubKey       string `json:"pubkey"`     // base64 peer static key
	Role         string `json:"role"`       // "initiator" or "responder"
	Approved     bool   `json:"approved"`   // admission control: peer is admin-approved
	PostQuantum  bool   `json:"post_quantum"` // peer's advertised live PQ state
	Established  bool   `json:"established"`
	Exit         bool   `json:"exit"`        // peer advertises as an internet exit node
	ExitFailed   bool   `json:"exit_failed"` // peer WANTS to be an exit but its NAT setup failed (gossiped)
	V6           bool   `json:"v6"`          // peer has a globally routable IPv6 transport address (gossiped)
	// IPDerived: the overlay IP shown is a GUESS derived from the peer's
	// public key, because the peer has not announced one and no admin
	// provision exists. It is what that peer WOULD get by default, but it is
	// not confirmed — and presenting a guess identically to a known address
	// is how a peer ends up "showing the wrong IP" in the UI.
	IPDerived    bool   `json:"ip_derived"`
	ActiveExit   bool   `json:"active_exit"` // the exit THIS device currently egresses through
	Relayed      bool   `json:"relayed"`     // reachable only via a relay (no direct session)
	Via          string `json:"via"`         // relayed rows: the relaying node (overlay IP or endpoint)
	SinceUnix    int64  `json:"since_unix"`     // when the session was created
	LastSeenUnix int64  `json:"last_seen_unix"` // last inbound activity
}

// RevocationInfo is the JSON view of one admin-signed revocation, for the
// dashboard's "revoked peers" list.
type RevocationInfo struct {
	PubKey    string `json:"pubkey"`
	KeyFP     string `json:"key_fp"`
	OverlayIP string `json:"overlay_ip"`
	Name      string `json:"name"`
	Action    string `json:"action"`
	Seq       int64  `json:"seq"`
	Ts        int64  `json:"ts"`
	Signed    bool   `json:"signed"`
}

// resolvePeerIP returns the best-known overlay IP for a peer key: its announced
// IP, then an admin-assigned (provisioned) address, then the key-derived IP.
func resolvePeerIP(pub [32]byte) string {
	if ip := peerOverlayIPByPub(pub); ip != "" {
		return ip
	}
	if rec, ok := provisions.get(pub); ok && rec.Address != "" {
		return stripMask(normalizeOverlayAddr(rec.Address))
	}
	if overlayCIDR != "" {
		if d, err := deriveOverlayIP(overlayCIDR, pub); err == nil {
			return stripMask(d)
		}
	}
	return ""
}

// syncAdminStateTo pushes the full admin/network state to a single peer that
// just connected: the admin-key seed + sealed blob, all signed records
// (revocations, approvals, provisions), our friendly name, and the current
// network config + policy. This is the primary delivery path — the keepalive
// loop only re-floods this set on a slow (~5 min) safety cadence, so a fresh or
// reconnecting peer converges instantly without steady per-tick bandwidth.
func syncAdminStateTo(raddr *net.UDPAddr) {
	if GlobalSessions == nil || GlobalConn == nil {
		return
	}
	s := GlobalSessions.GetByAddr(raddr)
	if s == nil || !s.Established() {
		return
	}
	send := func(f []byte) {
		if f != nil {
			_ = sendPacket(GlobalConn, raddr, s, f)
		}
	}
	send(buildAdminSeed())
	send(buildSealedKeyFrame())
	send(buildNameAnnounce())
	for _, e := range revocations.list() {
		if e.Signed && e.Rec != nil {
			send(buildRevocationFrame(*e.Rec))
		}
	}
	for _, e := range approvals.list() {
		if e.Rec != nil {
			send(buildApprovalFrame(*e.Rec))
		}
	}
	for _, rec := range provisions.list() {
		send(buildProvisionFrame(rec))
	}
	if nc, ok := persistedNetConfig(); ok {
		send(buildNetConfigFrame(nc))
	}
	policyMu.Lock()
	pols := make([]SignedPolicy, 0, len(nodePolicies))
	for _, p := range nodePolicies {
		pols = append(pols, p)
	}
	policyMu.Unlock()
	for _, p := range pols {
		send(buildPolicyFrame(p))
	}
}

// adminSourceLabel describes the peer that sent an admin-key frame, for logs:
// its UDP endpoint plus (if known) its overlay IP and key fingerprint, so you can
// track down which node is seeding a stray admin key.
func adminSourceLabel(raddr *net.UDPAddr) string {
	label := raddr.String()
	if s := GlobalSessions.GetByAddr(raddr); s != nil {
		var zero [32]byte
		if s.peerStatic != zero {
			extra := "key " + peerKeyFingerprint(s.peerStatic[:])
			if ip := resolvePeerIP(s.peerStatic); ip != "" {
				extra = "overlay " + ip + ", " + extra
			}
			if n := resolvePeerName(s.peerStatic); n != "" {
				extra = "\"" + n + "\", " + extra
			}
			label += " (" + extra + ")"
		}
	}
	return label
}

// resolvePeerName returns the best-known friendly name for a peer key.
func resolvePeerName(pub [32]byte) string {
	if n := peerNameByPub(pub); n != "" {
		return n
	}
	if rec, ok := provisions.get(pub); ok && rec.Name != "" {
		return rec.Name
	}
	return ""
}

func peerKeyFingerprint(pub []byte) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:6])
}

// publicIPOnly returns just the host part of the STUN reflexive endpoint
// ("203.0.113.7" from "203.0.113.7:6969"), or "" when unknown.
func publicIPOnly() string {
	ep := currentPublicEndpoint()
	if ep == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(ep); err == nil {
		return host
	}
	return ep
}

func stripMask(cidr string) string {
	if i := strings.IndexByte(cidr, '/'); i >= 0 {
		return cidr[:i]
	}
	return cidr
}

// Snapshot returns a point-in-time view of all sessions for the admin UI. All
// session fields are read under the table lock; the overlay-IP resolution
// (which takes other locks) is done afterward on copied data.
func (t *SessionTable) Snapshot() []SessionInfo {
	type raw struct {
		info SessionInfo
		addr *net.UDPAddr
		key  [32]byte
	}

	t.mu.RLock()
	raws := make([]raw, 0, len(t.byAddr))
	for k, s := range t.byAddr {
		info := SessionInfo{
			Remote:       k,
			Established:  s.established,
			SinceUnix:    s.createdAt.Unix(),
			LastSeenUnix: s.lastSeen.Unix(),
			Role:         "responder",
		}
		if s.initiator {
			info.Role = "initiator"
		}
		if s.peerStatic != ([32]byte{}) {
			info.PubKey = base64.StdEncoding.EncodeToString(s.peerStatic[:])
			info.KeyFP = peerKeyFingerprint(s.peerStatic[:])
		}
		raws = append(raws, raw{info: info, addr: s.addr, key: s.peerStatic})
	}
	t.mu.RUnlock()

	// Collapse same-key entries: multiple sessions to one device are ROUTES
	// (LAN primary + WAN standby kept warm for roaming failover) — one
	// device, one row. Show only the primary: established beats not, a LAN
	// address beats a WAN one, then the most recently seen. The hidden
	// backup keeps working underneath; it simply isn't listed twice.
	best := map[[32]byte]int{}
	for i := range raws {
		if raws[i].key == ([32]byte{}) {
			continue
		}
		j, ok := best[raws[i].key]
		if !ok {
			best[raws[i].key] = i
			continue
		}
		a, b := raws[i], raws[j]
		better := false
		switch {
		case a.info.Established != b.info.Established:
			better = a.info.Established
		case isPrivateUDPAddr(a.addr) != isPrivateUDPAddr(b.addr):
			better = isPrivateUDPAddr(a.addr)
		default:
			better = a.info.LastSeenUnix > b.info.LastSeenUnix
		}
		if better {
			best[raws[i].key] = i
		}
	}
	primary := make([]raw, 0, len(raws))
	for i := range raws {
		if raws[i].key != ([32]byte{}) && best[raws[i].key] != i {
			continue // hidden backup route
		}
		primary = append(primary, raws[i])
	}
	raws = primary

	out := make([]SessionInfo, 0, len(raws))
	for _, r := range raws {
		info := r.info
		// Prefer the peer's own announced overlay IP (authoritative, updates on
		// re-address); then the routing table; then an ADMIN-ASSIGNED address
		// from a provision (for peers whose keepalives haven't reached us yet but
		// whose signed provision has — we knew the name from it but were showing
		// a key-derived IP); then the key-derived fallback.
		ip := peerOverlayIPByPub(r.key)
		if ip == "" {
			ip = ipLearning.OverlayIPFor(r.addr)
		}
		if ip == "" {
			if rec, ok := provisions.get(r.key); ok && rec.Address != "" {
				ip = stripMask(normalizeOverlayAddr(rec.Address))
				if ip != "" && r.addr != nil {
					ipLearning.Learn(ip, r.addr) // so traffic to the assigned IP routes to this peer
				}
			}
		}
		derived := false
		if ip == "" && overlayCIDR != "" && r.key != ([32]byte{}) {
			if d, err := deriveOverlayIP(overlayCIDR, r.key); err == nil {
				ip = stripMask(d)
				derived = true // a guess, not an announced address
			}
		}
		info.OverlayIP = ip
		info.IPDerived = derived
		info.Name = peerNameByPub(r.key)
		info.Approved = admitted(r.key)
		info.PostQuantum = peerPQByPub(r.key)
		info.Exit, info.ActiveExit = exitStatusFor(r.key)
		// Merge the gossiped roster view into the direct row. Exit capability
		// deliberately has REDUNDANT paths to the UI: the peer's own 'E'
		// announce over this session, its self-report in its roster, and
		// every OTHER node's roster view of it. Any one of them lights the
		// green E — so one flaky link can't hide the only exit on the mesh.
		// (exitStatusFor stays authoritative for ACTIVE exit selection; the
		// roster only widens what is DISPLAYED.) A failed exit never
		// announces at all, so its failure flag can ONLY come from gossip.
		if rv, ok := rosterLookup(ip); ok {
			info.Exit = info.Exit || rv.Exit
			info.ExitFailed = rv.ExitErr
			info.V6 = rv.V6
		}
		out = append(out, info)
	}

	// RELAY-ONLY peers. The list above is built purely from DIRECT sessions, so
	// a peer we can only reach through another node's relay is invisible even
	// though traffic to it works. Surface those from the routing table, but
	// tightly filtered so we never show junk or duplicates:
	//   * overlay-range IPs ONLY — never internet destinations learned while an
	//     exit node is in use (that was surfacing public IPs),
	//   * only when the next hop is a LIVE session that is NOT the peer's own
	//     endpoint (i.e. a genuine relay, not a direct peer or a stale route),
	//   * deduped against the direct list by overlay IP AND by device key, so a
	//     peer that also has a direct route never appears twice and the relayed
	//     row disappears the moment a direct route forms.
	if ipLearning != nil {
		directIPs := map[string]bool{}
		directKeys := map[[32]byte]bool{}
		directFPs := map[string]bool{}
		for _, si := range out {
			if si.OverlayIP != "" {
				directIPs[si.OverlayIP] = true
			}
			if si.KeyFP != "" {
				directFPs[si.KeyFP] = true
			}
		}
		for _, r := range raws {
			if r.key != ([32]byte{}) {
				directKeys[r.key] = true
			}
		}
		var overlayNet *net.IPNet
		if overlayCIDR != "" {
			if _, n, err := net.ParseCIDR(overlayCIDR); err == nil {
				overlayNet = n
			}
		}
		seen := map[string]bool{}
		for _, e := range ipLearning.Entries() {
			if e.IP == "" || e.IP == myOverlayIP() || directIPs[e.IP] || seen[e.IP] {
				continue
			}
			// Overlay range only — drops internet destinations (exit mode) and
			// anything else that isn't an overlay address.
			if overlayNet != nil {
				if pip := net.ParseIP(e.IP); pip == nil || !overlayNet.Contains(pip) {
					continue
				}
			}
			// The next hop must be a live session, and must be a RELAY — not the
			// endpoint's own peer (that would be a direct peer, already listed).
			hop := GlobalSessions.GetByAddr(e.Addr)
			if !hop.Established() || peerOverlayIPByPub(hop.peerStatic) == e.IP {
				continue
			}
			name, keyFP, key := relayPeerIdentity(e.IP)
			if key != ([32]byte{}) && directKeys[key] {
				continue // same device already has a direct route — not relayed
			}
			// Fill identity gaps from the gossip'd roster, including the
			// node's live post-quantum state (per-session PQ status frames
			// only flow over direct sessions, so without this a relayed
			// node always showed PQ off — the encryption was never dropped,
			// each hop is its own PQ-wrapped session; only the DISPLAY was
			// blind).
			pq := false
			exitCap := false
			if key != ([32]byte{}) {
				pq = peerPQByPub(key)
				exitCap, _ = exitStatusFor(key)
			}
			// pubKey is what the admin UI needs to ACT on this row — rename,
			// revoke, approve are all addressed to the full static key, and a
			// row without one can only be looked at. It comes from a stored
			// provision when we have one, else from the gossip'd roster.
			pubKey := ""
			if key != ([32]byte{}) {
				pubKey = base64.StdEncoding.EncodeToString(key[:])
			}
			if r, ok := rosterLookup(e.IP); ok {
				if name == "" {
					name = r.Name
				}
				if keyFP == "" {
					keyFP = r.FP
				}
				if pubKey == "" {
					pubKey = r.PK
				}
				if !pq {
					pq = r.PQ
				}
				// Exit capability travels in the roster for the same reason
				// PQ does: the 'E' announce only flows over direct sessions.
				if !exitCap {
					exitCap = r.Exit
				}
			}
			// The same DEVICE may already be listed directly under a
			// different resolved IP (announce raced the snapshot, or a
			// key-derived fallback address) — never show it twice, once
			// "direct" and once "relayed".
			if keyFP != "" && directFPs[keyFP] {
				continue
			}
			// Register this row's identity so LATER relay rows dedup against it
			// too. These sets were built once from the direct rows and never
			// updated, so two relay rows for the SAME device under different
			// overlay addresses both survived — which is what happens whenever a
			// node is re-addressed and the old address is still inside its
			// roster TTL. The result was a peer count larger than the number of
			// devices, with the same machine listed twice.
			if keyFP != "" {
				directFPs[keyFP] = true
			}
			if key != ([32]byte{}) {
				directKeys[key] = true
			}
			seen[e.IP] = true
			// Which node is doing the relaying — its overlay IP when it has
			// announced one, else its UDP endpoint.
			via := peerOverlayIPByPub(hop.peerStatic)
			if via == "" && e.Addr != nil {
				via = e.Addr.String()
			}
			out = append(out, SessionInfo{
				// Relay-only rows have no direct UDP endpoint, but the client
				// UIs use Remote as the stable unique identity for a row. Give
				// each one a deterministic, unique key ("relay/<overlayIP>",
				// already deduped by IP above) so two relay peers — or a relay
				// peer whose key fingerprint / overlay IP happens to coincide
				// with another row — never collapse into a single list entry.
				Remote:       "relay/" + e.IP,
				Approved:     admittedB64(pubKey),
				OverlayIP:    e.IP,
				Name:         name,
				KeyFP:        keyFP,
				PubKey:       pubKey,
				PostQuantum:  pq,
				Exit:         exitCap,
				ExitFailed:   func() bool { rv, ok := rosterLookup(e.IP); return ok && rv.ExitErr }(),
				V6:           func() bool { rv, ok := rosterLookup(e.IP); return ok && rv.V6 }(),
				Established:  false,
				Relayed:      true,
				Via:          via,
				LastSeenUnix: e.Seen.Unix(),
			})
		}
	}

	// Gossip'd roster: nodes the network says exist but that this device has
	// neither a direct session nor a traffic-learned relay route to right
	// now. They're reachable through the relay flood (that's why pings work
	// even while they're missing), so list them as relayed instead of letting
	// them flicker in and out with the routing table's memory.
	{
		listed := map[string]bool{}
		listedFPs := map[string]bool{}
		for _, si := range out {
			if si.OverlayIP != "" {
				listed[si.OverlayIP] = true
			}
			if si.KeyFP != "" {
				listedFPs[si.KeyFP] = true
			}
		}
		myFP := peerKeyFingerprint(gKP.pub[:])
		var overlayNet *net.IPNet
		if overlayCIDR != "" {
			if _, n, err := net.ParseCIDR(overlayCIDR); err == nil {
				overlayNet = n
			}
		}
		for _, e := range rosterSnapshot() {
			if e.IP == myOverlayIP() || listed[e.IP] {
				continue
			}
			// Same DEVICE already listed (directly or via a relay route)
			// under a different resolved IP — or the roster echoing OUR OWN
			// node back at us under a stale address. One device, one row.
			if e.FP != "" && (e.FP == myFP || listedFPs[e.FP]) {
				continue
			}
			if overlayNet != nil {
				if pip := net.ParseIP(e.IP); pip == nil || !overlayNet.Contains(pip) {
					continue
				}
			}
			listed[e.IP] = true
			if e.FP != "" {
				listedFPs[e.FP] = true
			}
			name, keyFP, pubKey := e.Name, e.FP, e.PK
			if name == "" || keyFP == "" || pubKey == "" {
				n2, fp2, k2 := relayPeerIdentity(e.IP)
				if name == "" {
					name = n2
				}
				if keyFP == "" {
					keyFP = fp2
				}
				if pubKey == "" && k2 != ([32]byte{}) {
					pubKey = base64.StdEncoding.EncodeToString(k2[:])
				}
			}
			out = append(out, SessionInfo{
				Remote:       "known/" + e.IP,
				Approved:     admittedB64(pubKey),
				OverlayIP:    e.IP,
				Name:         name,
				KeyFP:        keyFP,
				PubKey:       pubKey,
				PostQuantum:  e.PQ,
				Exit:         e.Exit,
				ExitFailed:   e.ExitErr,
				V6:           e.V6,
				Established:  false,
				Relayed:      true,
				LastSeenUnix: e.Seen.Unix(),
			})
		}
	}

	// HEARD THROUGH THE MESH: nodes whose relayed control frames are arriving
	// right now, but which are in neither the routing table nor the roster.
	//
	// A node that can dial out but never be dialled — anything behind a
	// symmetric NAT, including an overlay client running inside a Kubernetes
	// pod behind CNI masquerade — holds zero direct sessions. Nothing
	// advertises it into the roster (roster.go gossips only DIRECT peers, one
	// hop), and ip_learning drops it as soon as data traffic pauses. It was
	// therefore reachable and serving traffic while appearing nowhere in this
	// list, which reads as "the node is gone" when it plainly isn't.
	//
	// Its connect requests/acks are the proof of life the other two sources
	// lack, so they get their own row source here. Listed LAST so a direct
	// session or a real learned route always wins the row. See heard.go.
	{
		listed := map[string]bool{}
		listedFPs := map[string]bool{}
		for _, si := range out {
			if si.OverlayIP != "" {
				listed[si.OverlayIP] = true
			}
			if si.KeyFP != "" {
				listedFPs[si.KeyFP] = true
			}
		}
		myFP := peerKeyFingerprint(gKP.pub[:])
		var overlayNet *net.IPNet
		if overlayCIDR != "" {
			if _, n, err := net.ParseCIDR(overlayCIDR); err == nil {
				overlayNet = n
			}
		}
		for ip, h := range heardSnapshot() {
			if ip == myOverlayIP() || listed[ip] {
				continue
			}
			// Overlay range only, mirroring the relay-route filter above: a
			// forged or malformed source IP never becomes a row.
			if overlayNet != nil {
				if pip := net.ParseIP(ip); pip == nil || !overlayNet.Contains(pip) {
					continue
				}
			}
			name, keyFP, key := relayPeerIdentity(ip)
			pubKey := ""
			if key != ([32]byte{}) {
				pubKey = base64.StdEncoding.EncodeToString(key[:])
			}
			if r, ok := rosterLookup(ip); ok {
				if name == "" {
					name = r.Name
				}
				if keyFP == "" {
					keyFP = r.FP
				}
				if pubKey == "" {
					pubKey = r.PK
				}
			}
			// One device, one row — never echo ourselves back, and never show
			// a device that is already listed under a different resolved IP.
			if keyFP != "" && (keyFP == myFP || listedFPs[keyFP]) {
				continue
			}
			listed[ip] = true
			if keyFP != "" {
				listedFPs[keyFP] = true
			}
			out = append(out, SessionInfo{
				Remote:       "heard/" + ip,
				Approved:     admittedB64(pubKey),
				OverlayIP:    ip,
				Name:         name,
				KeyFP:        keyFP,
				PubKey:       pubKey,
				Established:  false,
				Relayed:      true,
				Via:          h.Via,
				LastSeenUnix: h.Seen.Unix(),
			})
		}
	}
	return out
}

// relayPeerIdentity returns a best-effort friendly name, key fingerprint, and
// static key for a relay-only peer, matched by overlay IP against admin-signed
// provisions — the only IP-keyed identity we might hold for a peer we have no
// direct session to. All zero when the peer isn't provisioned (the row still
// shows its overlay IP); the returned key lets the caller dedupe against a
// direct route to the same device.
// admittedB64 reports whether a base64 static key is admitted by admission
// control. An empty or malformed key reports TRUE: a row whose identity we
// could not establish must not be labelled "pending", which would invite an
// approval the UI has no key to send.
func admittedB64(b64 string) bool {
	if b64 == "" {
		return true
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return true
	}
	var pub [32]byte
	copy(pub[:], raw)
	return admitted(pub)
}


// peerPubByOverlayIP resolves an overlay address back to the device's full
// static public key, using the announce table every node maintains.
//
// This is what makes the admin actions work on a RELAYED row. Edit, Revoke and
// Approve are all addressed to a full public key; a relayed row carries only
// what gossip gave it, which is a truncated fingerprint. The previous lookup
// searched stored provisions, so the buttons appeared only for devices an admin
// had already renamed or re-addressed — i.e. almost never, and never for the
// device you had just noticed and wanted to act on.
//
// peerOverlayIPs is populated from each peer's own address announce, which
// reaches us over the relay flood as readily as over a direct session, and is
// filled in regardless of what build the peer runs. So any node that has ever
// announced itself to us is resolvable here, with no dependency on roster
// gossip carrying the key.
func peerPubByOverlayIP(ip string) ([32]byte, bool) {
	var zero [32]byte
	if ip == "" {
		return zero, false
	}
	nameMu.Lock()
	defer nameMu.Unlock()
	for pub, got := range peerOverlayIPs {
		if got == ip && pub != zero {
			return pub, true
		}
	}
	return zero, false
}

func relayPeerIdentity(ip string) (name, keyFP string, key [32]byte) {
	for _, rec := range provisions.list() {
		if rec.Address == "" || stripMask(normalizeOverlayAddr(rec.Address)) != ip {
			continue
		}
		name = rec.Name
		if raw, err := base64.StdEncoding.DecodeString(rec.PubKey); err == nil && len(raw) == 32 {
			copy(key[:], raw)
			keyFP = peerKeyFingerprint(raw)
		}
		return name, keyFP, key
	}
	// No provision for this address — fall back to the announce table, which
	// covers every node that has ever told us its overlay IP. Without this the
	// admin buttons on a relayed row only ever appeared for a device that had
	// already been provisioned.
	if pub, ok := peerPubByOverlayIP(ip); ok {
		return peerNameByPub(pub), peerKeyFingerprint(pub[:]), pub
	}
	return "", "", key
}

// RevokeByRemote tears down the session to the given UDP endpoint, forgets its
// overlay-IP mappings, and adds the peer's static key to the revocation list
// so it cannot immediately re-handshake. Returns false if no such session.
func (t *SessionTable) RevokeByRemote(remote string) bool {
	t.mu.Lock()
	s := t.byAddr[remote]
	if s == nil {
		t.mu.Unlock()
		return false
	}
	key := s.peerStatic
	// Tear down EVERY route to this device, not just the listed one — peers
	// may hold a hidden backup session (LAN + WAN roaming routes), and a
	// revoked node must not stay reachable through its standby path.
	addrs := []*net.UDPAddr{}
	for k, o := range t.byAddr {
		if k == remote || (key != ([32]byte{}) && o.peerStatic == key) {
			delete(t.byAddr, k)
			if o.addr != nil {
				addrs = append(addrs, o.addr)
			}
		}
	}
	cb := t.onSessionLost
	t.mu.Unlock()

	// Record a local (unsigned) revocation so the peer is blocked from
	// reconnecting and shows up in the dashboard's revoked list with an Accept
	// button. This node only — network-wide requires the signed path.
	revocations.applyLocal(key, "revoke")
	// All routes are gone — forget the negotiated PQ layer so a re-admitted
	// peer renegotiates cleanly.
	pqForget(key)
	forgetPeerPQStatus(key)
	for _, a := range addrs {
		ipLearning.ForgetAddr(a)
		if cb != nil {
			go cb(a)
		}
	}
	log.Printf("[admin] revoked session %s and %d route(s) (key %s)", remote, len(addrs), peerKeyFingerprint(key[:]))
	return true
}

// --- control HTTP server (unix socket) ------------------------------------

// anotherClientIsLive reports whether a FULLY STARTED client owns socketPath.
//
// A bare Dial is not enough, and the difference is a deadlock. An UNCONFIGURED
// client serves the first-run setup UI on this very socket (see
// runSetupServerAndWait), so "the socket answers" is also true when the only
// thing running is a node waiting to be told its network name. Treating that as
// "already running" wedges the machine permanently: the setup server holds the
// socket forever, and every properly configured client that tries to start
// refuses and exits. Nothing ever connects, and the log says only that another
// client is already running.
//
// So ask for /api/info and require a public key in the reply. Only a client
// that finished startup can produce one; the setup server cannot, and is
// correctly treated as replaceable.
func anotherClientIsLive(socketPath string) bool {
	if socketPath == "" {
		return false
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	c := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	resp, err := c.Get("http://unix/api/info")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var m struct {
		PublicKey string `json:"public_key"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&m) != nil {
		return false
	}
	return m.PublicKey != ""
}

func startControlServer(socketPath string) {
	// SINGLE-INSTANCE GUARD. This used to unconditionally os.Remove the
	// socket and listen — silently STEALING it from an already-running
	// client. The old process kept running headless (holding its utun, its
	// UDP port, and its node key), so the machine ended up with TWO overlay
	// identities fighting over one pinned overlay IP: the node handshakes
	// with itself, peers see an address conflict, and the shared log shows
	// every line twice. If the socket answers, another instance is alive —
	// refuse to start instead of shouldering past it.
	if anotherClientIsLive(socketPath) {
		log.Fatalf("[control] another overlay client is ALREADY RUNNING (control socket %s is live). "+
			"Stop it first (macOS: sudo pkill -f overlay-client) — running two instances gives this "+
			"machine two identities and breaks the mesh.", socketPath)
	}
	// No live responder — any leftover socket file is stale (unclean shutdown).
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Printf("[control] cannot listen on %s: %v", socketPath, err)
		return
	}
	// 0666 so a non-root client (e.g. the macOS menu-bar app running as the
	// user, while the overlay client runs as root) can reach the socket. It's
	// still protected by the parent directory's permissions (~/.apgo is 0700
	// on macOS; the shared volume is private to the two containers on Linux).
	_ = os.Chmod(socketPath, 0o666)

	mux := http.NewServeMux()

	mux.HandleFunc("/api/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"overlay_ip":      myOverlayIP(),
			"public_key":      base64.StdEncoding.EncodeToString(gKP.pub[:]),
			"key_fp":          peerKeyFingerprint(gKP.pub[:]),
			"friendly_name":   getMyFriendlyName(),
			"pending_address": getPendingAddress(),
			// This node's public (STUN reflexive) endpoint: "ip:port", or "" if
			// STUN hasn't succeeded yet. public_ip is the host part alone for
			// simple display.
			"public_endpoint": currentPublicEndpoint(),
			"public_ip":       publicIPOnly(),
			// admin_trusted: this node trusts a network admin public key (so the
			// network HAS an admin key), even if the encrypted blob for signing
			// hasn't synced here yet.
			"admin_trusted":  adminKeySet(),
			// Admission control: whether the network gates new devices, and whether
			// THIS node has been approved (used by the mobile "pending" banner).
			"admission_required": admissionRequired(),
			"self_approved":      selfApproved(),
			// Current network-wide post-quantum state (admin-signed policy).
			"post_quantum": pqEnabled,
			// Local transport toggles (per-node).
			"ipv6":               ipv6Enabled,
			"pq_auth":            pqAuth,
			"port_prediction":    portPredictionOn.Load(),
			// How this node's NAT allocates external ports. "symmetric" means
			// peers behind their own NAT cannot punch to us and will relay —
			// the one diagnosis the UI previously had no way to show.
			"nat":                natSummary(),
			"nat_type":           natTypeLabel(),
			"uptime_seconds":     int64(time.Since(nodeStartTime).Seconds()),
			// Distinct DEVICES, not sessions: a peer reached over both its LAN
			// and WAN address holds two established sessions, and the peer table
			// collapses those into one row. Counting addresses here made the
			// card disagree with the table underneath it.
			"sessions":           GlobalSessions.EstablishedPeerCount(),
			"session_routes":     len(GlobalSessions.EstablishedAddrs()),
			// Full-VPN state: whether this node routes internet traffic via an
			// exit, which exit is pinned ("" = automatic/fastest), and which exit
			// is currently carrying traffic.
			"use_exit":     useExit,
			"exit_pin":     currentExitPin(),
			"current_exit": currentExitSummary(),
			// Whether THIS node is an exit (EXIT_NODE / exit_node, with NAT
			// successfully enabled). The sessions table can only badge PEERS
			// (they announce 'E' over their sessions), so without this field
			// an exit node's own dashboard showed no green E anywhere — the
			// one node guaranteed to be an exit was the one place it was
			// invisible.
			"exit_node": amExit,
			// Non-empty when exit-node mode was REQUESTED but NAT setup
			// failed (the node then refuses to advertise rather than
			// black-hole clients). Dashboards surface this string.
			"exit_node_error": exitNATErr,
			// Non-empty when the overlay CIDR collides with a physical
			// network this machine is on — a config error that breaks exit
			// return-routing and makes peer IPs ambiguous.
			"overlay_lan_conflict": overlayLANConflict,
			// IPv6 TRANSPORT reachability. "Does this node have a globally
			// routable IPv6 address it can be dialled on?" — the single fact
			// that decides whether a peer pair can skip NAT traversal
			// entirely. Two nodes that BOTH report true should never need a
			// relay; a node reporting false can only be reached over IPv4,
			// with all the NAT rules that implies. Reported per node so the
			// dashboard can say WHICH end lacks it instead of leaving
			// "should we go IPv6?" to guesswork.
			"ipv6_global":    hasGlobalIPv6(),
			"ipv6_endpoints": globalIPv6Endpoints(myUDPPort),
			// INBOUND REACHABILITY — has any off-LAN peer ever completed a
			// handshake TOWARD this node? "false" while peers exist is the
			// signature of a firewall dropping inbound UDP on our port, which
			// is the most common reason a node is permanently relayed.
			"inbound_ok": func() bool { ok, _, _ := inboundStatus(); return ok }(),
			"inbound_last_unix": func() int64 { _, l, _ := inboundStatus(); return l }(),
			"inbound_from":      func() string { _, _, f := inboundStatus(); return f }(),
			"listen_port":       myUDPPort,
			"advertise_port":    advertisePort,
			// WHAT WE TELL PEERS TO DIAL. This is the single most useful fact
			// for "why is this node relayed", and it was invisible: if the
			// list is EMPTY (STUN blocked, no LAN address a peer could use,
			// no configured candidate) then peers have nothing to dial and
			// relay is guaranteed — with no firewall involved at all. A
			// Kubernetes pod is the classic case: cluster-internal pod IP,
			// egress-only network, STUN filtered.
			"my_candidates": myConnectCandidates(),
			// behind_router: our STUN-observed public IP is not an address on
			// any local interface, so at least one NAT sits between us and the
			// internet that we do NOT control from this host. It decides
			// whether "open the port" means a HOST firewall rule or a ROUTER
			// port-forward — advice that is useless (and misleading) if it
			// names the wrong device. A Kubernetes pod on a LAN node is
			// behind two: the CNI masquerade and the site router.
			"behind_router": behindRouter(),
			"local_v4":      localIPv4Strings(),
			"nat_advice": func() string {
				p := advertisePort
				if p == 0 {
					p = myUDPPort
				}
				return natTraversalAdvice(p)
			}(),
		})
	})

	// Known exit nodes (outproxies), with latency + which one is selected —
	// lets a UI render a "choose your exit" picker.
	mux.HandleFunc("/api/exits", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"use_exit": useExit,
			"pin":      currentExitPin(),
			"exits":    exitCandidateList(),
		})
	})

	// Set the outproxy selection mode: {"pin":""} = automatic (fastest exit),
	// {"pin":"10.22.55.7"} (or a friendly name / base64 key / fingerprint
	// prefix) = always egress via that node. Applies live within seconds and
	// persists across restarts when NODE_SETTINGS_FILE is configured.
	mux.HandleFunc("/api/exit-pin", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Pin string `json:"pin"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		pin := strings.TrimSpace(req.Pin)
		setExitPin(pin)
		persisted := saveNodeExitPin(pin) == nil
		if pin == "" {
			log.Printf("[exit] outproxy selection set to automatic (fastest)")
		} else {
			log.Printf("[exit] outproxy pinned to %q", pin)
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pin": pin, "persisted": persisted})
	})

	// Admin-signed device approval (admission control): verify, apply, gossip now.
	mux.HandleFunc("/api/approve-signed", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var rec SignedApproval
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		pub, ok := verifyApproval(rec)
		if !ok {
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}
		approvals.applySigned(rec, pub)
		if f := buildApprovalFrame(rec); f != nil && GlobalSessions != nil && GlobalConn != nil {
			for _, addr := range GlobalSessions.EstablishedAddrs() {
				if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
					_ = sendPacket(GlobalConn, addr, s, f)
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	// Admin-signed network name/PSK rotation: verify, persist, gossip, restart.
	mux.HandleFunc("/api/network-config-signed", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var nc SignedNetworkConfig
		if err := json.NewDecoder(r.Body).Decode(&nc); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if !verifyNetConfig(nc) {
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		go adoptNetConfig(nc) // persists, floods, then restarts this node
	})

	// Admin-signed network policy (post-quantum on/off): verify, apply LIVE, gossip.
	mux.HandleFunc("/api/policy-signed", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var p SignedPolicy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if !verifyPolicy(p) {
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}
		adoptPolicy(p)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "post_quantum": pqEnabled})
	})

	// Generate a fresh random PSK ("base64:<32 bytes>") for the admin UI.
	mux.HandleFunc("/api/gen-psk", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"psk": generatePSK()})
	})

	// Current epoch of the applied network config (0 = original).
	mux.HandleFunc("/api/net-epoch", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"epoch": currentNetEpoch.Load()})
	})

	// Tracker management: GET the effective list; POST a replacement list (the
	// announce loops pick it up on the next tick — no restart).
	mux.HandleFunc("/api/trackers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req struct {
				Trackers []string `json:"trackers"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			// Refuse to save an empty list — that would leave the node with no way
			// to discover peers. Keep at least one tracker.
			nonEmpty := 0
			for _, t := range req.Trackers {
				if strings.TrimSpace(t) != "" {
					nonEmpty++
				}
			}
			if nonEmpty == 0 {
				http.Error(w, "keep at least one tracker", http.StatusBadRequest)
				return
			}
			if err := saveTrackers(req.Trackers); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "trackers": currentTrackers()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"trackers": currentTrackers()})
	})

	mux.HandleFunc("/api/sessions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, GlobalSessions.Snapshot())
	})

	// Join details for building a "join QR" on the admin panel. Contains the PSK,
	// so it is only ever served on the localhost/unix control socket and is gated
	// behind the admin login on the dashboard that renders the QR.
	mux.HandleFunc("/api/join-info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"network_name":       gNetworkName,
			"psk":                gPSKString,
			"overlay_cidr":       overlayCIDR,
			"rendezvous_servers": gRendezvous,
			// The rendezvous credential travels with the join details so a
			// phone that scans the QR can actually USE the server. It is no
			// more sensitive than the PSK sitting next to it, and this page
			// is already admin-authenticated.
			"rendezvous_auth": gRendezvousCred,
			// Top trackers so a scanned phone uses this network's discovery
			// (incl. any private tracker) instead of only its compiled-in
			// defaults. Capped so the QR stays small enough to scan.
			"trackers": topN(currentTrackers(), 8),
			// Crypto settings ride along so a joining device matches this node
			// exactly — mismatches fail every handshake silently.
			"cipher":       gCipherName,
			"post_quantum": pqEnabled,
			"pq_auth":      pqAuth,
		})
	})

	mux.HandleFunc("/api/revoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Remote string `json:"remote"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Remote == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if GlobalSessions.RevokeByRemote(req.Remote) {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "remote": req.Remote})
			return
		}
		http.Error(w, "session not found", http.StatusNotFound)
	})

	// List the current admin-signed revocations (for the dashboard's
	// "revoked peers" panel, with an Accept/restore button).
	mux.HandleFunc("/api/revocations", func(w http.ResponseWriter, r *http.Request) {
		recs := revocations.list()
		out := make([]RevocationInfo, 0, len(recs))
		for _, rec := range recs {
			info := RevocationInfo{PubKey: rec.PubKey, Action: rec.Action, Seq: rec.Seq, Ts: rec.Ts, Signed: rec.Signed}
			if raw, err := base64.StdEncoding.DecodeString(rec.PubKey); err == nil && len(raw) == 32 {
				info.KeyFP = peerKeyFingerprint(raw)
				var k [32]byte
				copy(k[:], raw)
				info.OverlayIP = resolvePeerIP(k)
				info.Name = resolvePeerName(k)
			}
			out = append(out, info)
		}
		writeJSON(w, http.StatusOK, out)
	})

	// Accept (re-admit) a LOCAL, unsigned revocation. Signed revocations must
	// be lifted with a signed "restore" instead.
	mux.HandleFunc("/api/local-restore", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			PubKey string `json:"pubkey"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PubKey == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(req.PubKey)
		if err != nil || len(raw) != 32 {
			http.Error(w, "bad pubkey", http.StatusBadRequest)
			return
		}
		var pub [32]byte
		copy(pub[:], raw)
		if revocations.removeLocal(pub) {
			log.Printf("[admin] local revocation lifted for key %s", peerKeyFingerprint(pub[:]))
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
			return
		}
		http.Error(w, "no local revocation for that key (a signed restore is required)", http.StatusBadRequest)
	})

	// Apply an admin-signed revoke/restore record: verify against the
	// configured admin public key, apply + persist, and tear down any matching
	// session. (Network-wide gossip of the record is added in the next stage.)
	mux.HandleFunc("/api/revoke-signed", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var rec SignedRevocation
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if len(adminPubBytes()) == 0 {
			http.Error(w, "no admin public key configured on this node (set ADMIN_PUBLIC_KEY)", http.StatusBadRequest)
			return
		}
		pub, ok := verifyRevocation(rec)
		if !ok {
			http.Error(w, "signature verification failed", http.StatusUnauthorized)
			return
		}
		changed, nowRevoked := revocations.applySigned(rec, pub)
		if nowRevoked {
			GlobalSessions.RevokeByKey(pub)
		}
		// Broadcast to peers immediately so the record reaches (and is enforced +
		// shown on) every node without waiting for the keepalive gossip tick.
		if frame := buildRevocationFrame(rec); frame != nil {
			for _, addr := range GlobalSessions.EstablishedAddrs() {
				if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
					_ = sendPacket(GlobalConn, addr, s, frame)
				}
			}
		}
		log.Printf("[admin] applied signed %s for key %s (seq %d, changed=%v)",
			rec.Action, peerKeyFingerprint(pub[:]), rec.Seq, changed)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": rec.Action, "changed": changed})
	})

	// Apply an admin-signed network share/unshare (join or leave a secondary
	// network): verify, store, gossip immediately, and apply if it targets this
	// node. The multi-network management endpoints live in multinet.go.
	mux.HandleFunc("/api/netshare-signed", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var rec SignedNetShare
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if len(adminPubBytes()) == 0 {
			http.Error(w, "no admin public key configured on this node", http.StatusBadRequest)
			return
		}
		if !verifyNetShare(rec) {
			http.Error(w, "signature verification failed", http.StatusUnauthorized)
			return
		}
		changed := netShares.apply(rec)
		if changed {
			applyNetShareSelf(rec)
		}
		// Flood immediately so the target (and every store-and-forward node)
		// gets it without waiting for the keepalive gossip tick.
		if frame := buildNetShareFrame(rec); frame != nil {
			for _, addr := range GlobalSessions.EstablishedAddrs() {
				if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
					_ = sendPacket(GlobalConn, addr, s, frame)
				}
			}
		}
		log.Printf("[admin] applied signed net-%s of %s for network %q (seq %d, changed=%v)",
			rec.Action, rec.PubKey[:min(12, len(rec.PubKey))], rec.NetworkName, rec.Seq, changed)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": rec.Action, "changed": changed})
	})

	// List stored share records (the panel shows which devices are shared into
	// which networks, and derives the next Seq).
	mux.HandleFunc("/api/netshares", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, netShares.list())
	})

	// Multi-network management: /api/networks, /api/network-add, -remove, -set.
	registerMultinetAPI(mux)

	// Apply an admin-signed provision (overlay IP and/or friendly name for a
	// target node): verify, store, gossip to peers immediately, and apply if it
	// targets this node.
	mux.HandleFunc("/api/provision-signed", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var rec SignedProvision
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if len(adminPubBytes()) == 0 {
			http.Error(w, "no admin public key configured on this node", http.StatusBadRequest)
			return
		}
		pub, ok := verifyProvision(rec)
		if !ok {
			http.Error(w, "signature verification failed", http.StatusUnauthorized)
			return
		}
		if !provisions.put(pub, rec) {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "changed": false})
			return
		}
		if rec.Name != "" {
			setPeerName(pub, rec.Name)
		}
		if pub == gKP.pub {
			applyProvisionSelf(rec)
		}
		// Broadcast the signed record to every established peer right away so it
		// reaches the target quickly (keepalive gossip keeps re-flooding it).
		if frame := buildProvisionFrame(rec); frame != nil {
			for _, addr := range GlobalSessions.EstablishedAddrs() {
				if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
					_ = sendPacket(GlobalConn, addr, s, frame)
				}
			}
		}
		log.Printf("[admin] applied signed provision for key %s (addr=%q name=%q seq=%d)",
			peerKeyFingerprint(pub[:]), rec.Address, rec.Name, rec.Seq)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "changed": true})
	})

	// Store/serve the password-encrypted admin key blob. The admin panel POSTs it
	// on create/password-change (distributing it network-wide); any node's admin
	// panel GETs it to sign with the admin password.
	mux.HandleFunc("/api/admin-key-sealed", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			blob := getSealedAdminKey()
			if blob == nil {
				http.Error(w, "no sealed admin key on this node", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(blob)
		case http.MethodPost:
			blob, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			// force=true: this comes from the authenticated local admin, so it may
			// establish/replace the key even if a stale public key was trusted.
			if !storeSealedAdminKeyForce(blob, true, true) {
				http.Error(w, "rejected (older than the key already stored)", http.StatusConflict)
				return
			}
			// Push it to peers immediately (keepalive gossip keeps re-flooding).
			if frame := buildSealedKeyFrame(); frame != nil {
				for _, addr := range GlobalSessions.EstablishedAddrs() {
					if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
						_ = sendPacket(GlobalConn, addr, s, frame)
					}
				}
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		default:
			http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
		}
	})

	// Set (and auto-seed to peers) the trusted admin public key. The local
	// admin app calls this after `genkey`, so nodes without an admin key learn
	// it automatically over the tunnel (trust-on-first-use).
	mux.HandleFunc("/api/set-admin-pubkey", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			PubKey string `json:"pubkey"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PubKey == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(req.PubKey)
		if err != nil || !adminPubValid(raw) {
			http.Error(w, "bad pubkey", http.StatusBadRequest)
			return
		}
		setAdminPub(raw, true)
		// Seed it to every established peer right away.
		if frame := buildAdminSeed(); frame != nil {
			for _, addr := range GlobalSessions.EstablishedAddrs() {
				if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
					_ = sendPacket(GlobalConn, addr, s, frame)
				}
			}
		}
		log.Printf("[admin] admin public key set locally and seeded to peers")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	// Per-node IPv6 transport toggle. Persists a local override (survives
	// restarts) and reports whether a restart is needed to apply it (changing
	// IPv6 re-binds the UDP socket, so it takes effect on the next start).
	// Rendezvous discovery config (servers + credential). Lets the admin panel
	// on a CONTAINERIZED node — where there is no desktop Settings window —
	// point the node at a discovery server without editing YAML and
	// redeploying. Persisted to node settings; applies on restart.
	mux.HandleFunc("/api/rendezvous-config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// Never echo the credential back — the panel shows whether one is
			// set, not what it is (same rule as every password field here).
			writeJSON(w, http.StatusOK, map[string]any{
				"servers":  gRendezvous,
				"auth_set": gRendezvousCred != "",
				"auth_user": func() string {
					if u, _, ok := strings.Cut(gRendezvousCred, ":"); ok {
						return u
					}
					return ""
				}(),
			})
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Servers []string `json:"servers"`
			User    string   `json:"user"`
			Pass    string   `json:"pass"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		clean := make([]string, 0, len(req.Servers))
		for _, s := range req.Servers {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
				http.Error(w, "rendezvous URLs must start with http:// or https://", http.StatusBadRequest)
				return
			}
			clean = append(clean, s)
		}
		// Recombine into the single credential string the client uses.
		auth := ""
		if u := strings.TrimSpace(req.User); u != "" {
			if p := strings.TrimSpace(req.Pass); p != "" {
				auth = u + ":" + p
			} else {
				auth = u
			}
		}
		if err := saveNodeRendezvous(clean, auth); err != nil {
			http.Error(w, "no persistent settings path configured on this node (set NODE_SETTINGS_FILE)", http.StatusBadRequest)
			return
		}
		// Apply the credential live; the server LIST is read at announce time
		// from cfg, so a restart is what makes new servers take effect.
		gRendezvousCred = auth
		log.Printf("[admin] rendezvous config updated — %d server(s), credential set=%v (restart to apply servers)",
			len(clean), auth != "")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "servers": clean, "auth_set": auth != ""})
	})

	mux.HandleFunc("/api/set-ipv6", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := saveNodeIPv6(req.Enabled); err != nil {
			http.Error(w, "no persistent settings path configured on this node (set NODE_SETTINGS_FILE)", http.StatusBadRequest)
			return
		}
		log.Printf("[admin] IPv6 transport set to %v (applies on restart)", req.Enabled)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "ipv6": req.Enabled, "restart_required": req.Enabled != ipv6Enabled,
		})
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("[control] admin control socket listening at %s", socketPath)
	if err := srv.Serve(ln); err != nil {
		log.Printf("[control] server stopped: %v", err)
	}
}

// topN returns at most the first n entries of s (for keeping the join QR small).
func topN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// --- exit (outproxy) views for the admin/UI --------------------------------

// ExitInfoView is the JSON view of one known exit node.
type ExitInfoView struct {
	OverlayIP string `json:"overlay_ip"`
	Name      string `json:"name"`
	KeyFP     string `json:"key_fp"`
	PubKey    string `json:"pubkey"`
	RttMs     int64  `json:"rtt_ms"` // -1 = not yet measured
	Reachable bool   `json:"reachable"`
	Selected  bool   `json:"selected"` // currently carrying this node's traffic
	Pinned    bool   `json:"pinned"`   // matches the configured pin
}

func currentExitPin() string {
	exitMu.Lock()
	defer exitMu.Unlock()
	return exitPin
}

// currentExitSummary describes the exit currently carrying traffic, or nil.
func currentExitSummary() map[string]any {
	exitMu.Lock()
	e := selectedExit
	var pub [32]byte
	var rtt int64
	if e != nil {
		pub, rtt = e.pub, e.rttMs
	}
	exitMu.Unlock()
	if e == nil {
		return nil
	}
	return map[string]any{
		"overlay_ip": resolvePeerIP(pub),
		"name":       resolvePeerName(pub),
		"key_fp":     peerKeyFingerprint(pub[:]),
		"rtt_ms":     rtt,
	}
}

// exitCandidateList snapshots every exit the mesh has advertised, for the
// "choose your exit" picker. Mutable exitInfo fields are copied under the
// lock; overlay IP / name resolution (which takes other locks) happens after.
func exitCandidateList() []ExitInfoView {
	type raw struct {
		pub       [32]byte
		addr      *net.UDPAddr
		rttMs     int64
		lastReply time.Time
		selected  bool
	}
	exitMu.Lock()
	pin := exitPin
	raws := make([]raw, 0, len(exitCandidates))
	for _, e := range exitCandidates {
		raws = append(raws, raw{
			pub: e.pub, addr: e.addr, rttMs: e.rttMs,
			lastReply: e.lastReply, selected: e == selectedExit,
		})
	}
	exitMu.Unlock()

	out := make([]ExitInfoView, 0, len(raws))
	for _, r := range raws {
		v := ExitInfoView{
			OverlayIP: resolvePeerIP(r.pub),
			Name:      resolvePeerName(r.pub),
			KeyFP:     peerKeyFingerprint(r.pub[:]),
			PubKey:    base64.StdEncoding.EncodeToString(r.pub[:]),
			RttMs:     -1,
			Selected:  r.selected,
			Pinned:    pin != "" && exitPinMatches(pin, r.pub),
		}
		if !r.lastReply.IsZero() {
			v.RttMs = r.rttMs
		}
		if s := GlobalSessions.GetByAddr(r.addr); s != nil && s.Established() &&
			time.Since(r.lastReply) <= 90*time.Second {
			v.Reachable = true
		}
		out = append(out, v)
	}
	return out
}
