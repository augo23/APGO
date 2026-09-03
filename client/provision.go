package main

// provision.go adds two related capabilities on top of the admin-key trust
// already used for revocations:
//
//   - friendly names: each node can advertise a human name (OVLYCTL1 N <name>),
//     shown next to its overlay IP in the admin dashboard.
//   - admin-signed provisioning: the admin (holder of the network admin key) can
//     assign a node a new overlay IP and/or friendly name. The record is
//     Ed25519-signed, gossiped across the mesh (OVLYCTL1 V <json>), verified
//     against the trusted admin public key, and applied by the target node: the
//     name takes effect live; the address is persisted and adopted on the node's
//     next (re)connect (uniform across every platform, incl. mobile).

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// --- friendly names ------------------------------------------------------

var (
	nameMu         sync.Mutex
	myFriendlyName string
	peerNames      = map[[32]byte]string{} // peer static key -> friendly name
	// peerOverlayIPs is each peer's OWN current overlay IP, as it announces it on
	// its direct session (via 'A' frames and keepalives). Keyed by static key and
	// overwritten on change, it's the authoritative source for the dashboard —
	// unlike the routing table, which can hold stale or relay-learned entries.
	peerOverlayIPs = map[[32]byte]string{}
)

func setPeerOverlayIP(pub [32]byte, ip string) {
	if ip == "" {
		return
	}
	nameMu.Lock()
	peerOverlayIPs[pub] = ip
	nameMu.Unlock()
}

func peerOverlayIPByPub(pub [32]byte) string {
	nameMu.Lock()
	defer nameMu.Unlock()
	return peerOverlayIPs[pub]
}

func sanitizeName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == '|' {
			return -1
		}
		return r
	}, s)
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}

func setMyFriendlyName(name string) {
	name = sanitizeName(name)
	nameMu.Lock()
	changed := myFriendlyName != name
	myFriendlyName = name
	nameMu.Unlock()
	if changed && name != "" {
		announceNameToPeers()
	}
}

func getMyFriendlyName() string {
	nameMu.Lock()
	defer nameMu.Unlock()
	return myFriendlyName
}

func setPeerName(pub [32]byte, name string) {
	name = sanitizeName(name)
	if name == "" {
		return
	}
	nameMu.Lock()
	peerNames[pub] = name
	nameMu.Unlock()
}

func peerNameByPub(pub [32]byte) string {
	nameMu.Lock()
	defer nameMu.Unlock()
	return peerNames[pub]
}

// buildNameAnnounce returns an "OVLYCTL1N<name>" control payload, or nil if this
// node has no friendly name set.
func buildNameAnnounce() []byte {
	n := getMyFriendlyName()
	if n == "" {
		return nil
	}
	out := append([]byte(nil), ctlMagic...)
	out = append(out, 'N')
	return append(out, []byte(n)...)
}

func announceNameToPeers() {
	frame := buildNameAnnounce()
	if frame == nil || GlobalSessions == nil || GlobalConn == nil {
		return
	}
	for _, addr := range GlobalSessions.EstablishedAddrs() {
		if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
			_ = sendPacket(GlobalConn, addr, s, frame)
		}
	}
}

// --- signed provisioning -------------------------------------------------

// SignedProvision assigns a node (identified by its static X25519 public key) a
// new overlay address and/or friendly name. Signed by the admin key; the signed
// bytes are defined by canonicalProvision and must match the signer exactly.
type SignedProvision struct {
	PubKey  string `json:"pubkey"`  // base64(std) target node static key
	Address string `json:"address"` // new overlay address ("10.22.55.42" or CIDR), or "" to leave unchanged
	Name    string `json:"name"`    // friendly name, or "" to leave unchanged
	Seq     int64  `json:"seq"`
	Ts      int64  `json:"ts"`
	Sig     string `json:"sig"` // base64(std) Ed25519 signature
}

func canonicalProvision(pubB64, address, name string, seq, ts int64) string {
	return fmt.Sprintf("OVLYPROV1|%s|%s|%s|%d|%d", pubB64, address, name, seq, ts)
}

// verifyProvision checks the signature against adminPub and returns the target
// 32-byte X25519 key on success.
func verifyProvision(rec SignedProvision) ([32]byte, bool) {
	var pub [32]byte
	if !adminKeySet() {
		return pub, false
	}
	raw, err := base64.StdEncoding.DecodeString(rec.PubKey)
	if err != nil || len(raw) != 32 {
		return pub, false
	}
	sig, err := base64.StdEncoding.DecodeString(rec.Sig)
	if err != nil {
		return pub, false
	}
	if !adminVerify([]byte(canonicalProvision(rec.PubKey, rec.Address, rec.Name, rec.Seq, rec.Ts)), sig) {
		return pub, false
	}
	copy(pub[:], raw)
	return pub, true
}

type provStore struct {
	mu   sync.Mutex
	recs map[[32]byte]SignedProvision
	path string
}

var provisions = &provStore{recs: map[[32]byte]SignedProvision{}}

// put stores rec if it supersedes the current entry for that target (higher
// seq), and retires any OTHER key's older claim on the same overlay address.
//
// Why the second half exists.
//
// A provision binds an overlay address to a PUBLIC KEY, and this store is
// keyed by key -- so before this, two keys could hold a provision for one
// address indefinitely and nothing ever retired the loser. That is not an
// exotic race: it is what an ordinary reinstall does. A wiped machine comes
// back with a fresh node.key, an admin assigns it its usual address, and the
// previous key's claim stays in every peer's store forever. Do it three times
// and three keys claim one address, of which two are machines that no longer
// exist.
//
// Retiring here rather than at the admin is deliberate. The stale records are
// already replicated across the mesh, so fixing only the issuing side would
// leave every existing copy in place; this rule runs on every node as the
// gossip arrives and heals stores that are already wrong. It is deterministic
// -- same records in, same records out, regardless of arrival order -- so
// nodes converge without extra traffic.
//
// The rule is strictly seq-ordered, never liveness-based. A quiet node has not
// stopped owning its address, and "silent for N minutes" would let any node
// squat a sleeping laptop's IP and inherit whatever that IP is trusted for.
// Only a NEWER admin signature displaces an older one.
func (s *provStore) put(pub [32]byte, rec SignedProvision) bool {
	s.mu.Lock()
	if cur, ok := s.recs[pub]; ok && rec.Seq <= cur.Seq {
		s.mu.Unlock()
		return false
	}
	s.recs[pub] = rec

	var retired []string
	if addr := normalizeOverlayAddr(rec.Address); addr != "" {
		ip := stripMask(addr)
		for k, other := range s.recs {
			if k == pub || other.Address == "" {
				continue
			}
			if stripMask(normalizeOverlayAddr(other.Address)) != ip {
				continue
			}
			// Only an older signature is displaced. If the other record is
			// newer, THIS one is the stale claim and the address belongs to
			// the other key -- leave it alone.
			if other.Seq < rec.Seq {
				delete(s.recs, k)
				retired = append(retired, peerKeyFingerprint(k[:]))
			}
		}
	}
	s.mu.Unlock()
	if len(retired) > 0 {
		log.Printf("[provision] %s reassigned to %s — retired %d superseded claim(s): %s",
			stripMask(normalizeOverlayAddr(rec.Address)), peerKeyFingerprint(pub[:]),
			len(retired), strings.Join(retired, ", "))
	}
	s.save()
	return true
}

func (s *provStore) get(pub [32]byte) (SignedProvision, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[pub]
	return r, ok
}

func (s *provStore) list() []SignedProvision {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SignedProvision, 0, len(s.recs))
	for _, r := range s.recs {
		out = append(out, r)
	}
	return out
}

func (s *provStore) save() {
	s.mu.Lock()
	path := s.path
	list := make([]SignedProvision, 0, len(s.recs))
	for _, r := range s.recs {
		list = append(list, r)
	}
	s.mu.Unlock()
	if path == "" {
		return
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err == nil {
		_ = os.Rename(tmp, path)
	}
}

// load reads persisted provisions, re-verifying each against adminPub.
func (s *provStore) load(path string) {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var list []SignedProvision
	if json.Unmarshal(data, &list) != nil {
		return
	}
	for _, rec := range list {
		pub, ok := verifyProvision(rec)
		if !ok {
			continue
		}
		s.mu.Lock()
		if cur, exists := s.recs[pub]; !exists || rec.Seq > cur.Seq {
			s.recs[pub] = rec
		}
		s.mu.Unlock()
		if rec.Name != "" {
			setPeerName(pub, rec.Name)
		}
	}
}

// buildProvisionFrame returns an "OVLYCTL1V<json>" control payload for gossip.
func buildProvisionFrame(rec SignedProvision) []byte {
	b, err := json.Marshal(rec)
	if err != nil {
		return nil
	}
	out := append([]byte(nil), ctlMagic...)
	out = append(out, 'V')
	return append(out, b...)
}

// pendingAddress holds an admin-assigned overlay address that takes effect on
// the next (re)connect. Surfaced to the supervising app via /api/info so it can
// prompt/auto-reconnect.
var (
	pendingAddrMu  sync.Mutex
	pendingAddress string
)

func getPendingAddress() string {
	pendingAddrMu.Lock()
	defer pendingAddrMu.Unlock()
	return pendingAddress
}

func normalizeOverlayAddr(a string) string {
	a = strings.TrimSpace(a)
	if a == "" {
		return ""
	}
	if strings.Contains(a, "/") {
		return a
	}
	ones := 24
	if overlayCIDR != "" {
		if _, ipnet, err := net.ParseCIDR(overlayCIDR); err == nil {
			ones, _ = ipnet.Mask.Size()
		}
	}
	return fmt.Sprintf("%s/%d", a, ones)
}

// handleProvision verifies a gossiped provision, stores it, records the name for
// display, and applies it if it targets this node.
func handleProvision(payload []byte) {
	var rec SignedProvision
	if json.Unmarshal(payload, &rec) != nil {
		return
	}
	pub, ok := verifyProvision(rec)
	if !ok {
		return
	}
	if !provisions.put(pub, rec) {
		return // not newer than what we already have
	}
	if rec.Name != "" {
		setPeerName(pub, rec.Name)
	}
	if pub == gKP.pub {
		applyProvisionSelf(rec)
	}
}

// overlayIPClaimants returns every OTHER node key that holds an admin
// provision for ip. Normally empty.
//
// A non-empty result is a DUPLICATE CLAIM on one overlay address, and it is the
// most quietly destructive state this system has. It happens when a machine is
// reinstalled: it comes back with a new node key, but the old key keeps its
// signed provision for the same address. Peers then resolve that address to a
// key that no longer exists anywhere, route to a dead endpoint, and the machine
// receives nothing — while its peer list, handshakes, post-quantum layers and
// gossip all look perfect, because control traffic is addressed to the SESSION
// and never to the overlay IP.
//
// From the affected node it presents as 100% packet loss with a completely
// healthy dashboard. Nothing in the peer list, the logs or the admission state
// hints at it. Hence this check, and the loud warning below.
func overlayIPClaimants(ip string) []string {
	if ip == "" {
		return nil
	}
	ip = strings.TrimSpace(strings.SplitN(ip, "/", 2)[0])
	self := base64.StdEncoding.EncodeToString(gKP.pub[:])
	var out []string
	for _, rec := range provisions.list() {
		if rec.PubKey == self || rec.Address == "" {
			continue
		}
		if strings.TrimSpace(strings.SplitN(rec.Address, "/", 2)[0]) == ip {
			out = append(out, rec.PubKey)
		}
	}
	return out
}

// warnOnDuplicateOverlayClaim logs, loudly and at most once a minute, when some
// other key also claims this node's overlay address. Rate-limited rather than
// once-only because the conflicting record can arrive by gossip long after
// startup.
var (
	dupClaimWarnMu   sync.Mutex
	dupClaimWarnLast time.Time
)

func warnOnDuplicateOverlayClaim() {
	mine := myOverlayIP()
	others := overlayIPClaimants(mine)
	if len(others) == 0 {
		return
	}
	dupClaimWarnMu.Lock()
	if time.Since(dupClaimWarnLast) < time.Minute {
		dupClaimWarnMu.Unlock()
		return
	}
	dupClaimWarnLast = time.Now()
	dupClaimWarnMu.Unlock()

	fps := make([]string, 0, len(others))
	for _, b64 := range others {
		if raw, err := base64.StdEncoding.DecodeString(b64); err == nil && len(raw) == 32 {
			fps = append(fps, peerKeyFingerprint(raw))
		}
	}
	log.Printf("[overlay] DUPLICATE CLAIM on %s: %d OTHER node key(s) hold an admin provision "+
		"for this address (%s). Peers resolve %s to one of THOSE keys, so traffic addressed to "+
		"this node is routed to a device that no longer exists — this node will appear fully "+
		"connected and receive NOTHING. This is the normal result of reinstalling a machine "+
		"(new node key, old provision left behind).",
		mine, len(others), strings.Join(fps, ", "), mine)
	log.Printf("[overlay] FIX: give this node a different overlay address, or have an admin "+
		"re-provision %s onto this node's current key (%s) — which supersedes the stale claims.",
		mine, peerKeyFingerprint(gKP.pub[:]))
}

// onPendingAddress, if set by the host (the standalone client, or a mobile
// bridge), is invoked when an admin assigns this node a NEW overlay address
// (different from the current one). The standalone client uses it to restart and
// adopt the address; mobile apps use it to warn + re-establish the tunnel.
var onPendingAddress func(newAddr string)

// applyProvisionSelf applies an admin provision addressed to this node: the name
// updates live; a new address is staged and the host is notified so it can
// restart the connection to adopt it.
func applyProvisionSelf(rec SignedProvision) {
	if rec.Name != "" {
		setMyFriendlyName(rec.Name)
		log.Printf("[provision] admin set this node's friendly name to %q", rec.Name)
	}
	if rec.Address != "" {
		addr := normalizeOverlayAddr(rec.Address)
		// Admin-assigned = pinned: conflict self-healing must never hop away
		// from an address the operator chose deliberately.
		addrAutoDerived = false
		if stripMask(addr) == myOverlayIP() {
			return // already on this address
		}
		pendingAddrMu.Lock()
		pendingAddress = addr
		pendingAddrMu.Unlock()
		log.Printf("[provision] admin assigned this node overlay address %s", addr)
		if onPendingAddress != nil {
			go onPendingAddress(addr)
		}
	}
}

// gossipNameAndProvisions broadcasts this node's friendly name and every stored
// provision to all established peers. Called on the keepalive tick; seq-based
// dedup on the receiving side stops the flood from looping.
func gossipNameAndProvisions() {
	if GlobalSessions == nil || GlobalConn == nil {
		return
	}
	nameFrame := buildNameAnnounce()
	recs := provisions.list()
	frames := make([][]byte, 0, len(recs))
	for _, rec := range recs {
		if f := buildProvisionFrame(rec); f != nil {
			frames = append(frames, f)
		}
	}
	if nameFrame == nil && len(frames) == 0 {
		return
	}
	for _, addr := range GlobalSessions.EstablishedAddrs() {
		s := GlobalSessions.GetByAddr(addr)
		if s == nil || !s.Established() {
			continue
		}
		if nameFrame != nil {
			_ = sendPacket(GlobalConn, addr, s, nameFrame)
		}
		for _, f := range frames {
			_ = sendPacket(GlobalConn, addr, s, f)
		}
	}
}

// adoptSelfProvisionAtStartup, called from main() before the TUN is created,
// applies any persisted admin-assigned address/name for THIS node.
func adoptSelfProvisionAtStartup(cfg *ClientConfig, selfPub [32]byte) {
	if rec, ok := provisions.get(selfPub); ok {
		if rec.Address != "" {
			cfg.Tun.AddressCIDR = normalizeOverlayAddr(rec.Address)
			log.Printf("[provision] adopting admin-assigned overlay address %s", cfg.Tun.AddressCIDR)
		}
		if rec.Name != "" {
			cfg.FriendlyName = rec.Name
		}
	}
}
