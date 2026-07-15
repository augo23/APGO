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
	Address string `json:"address"` // new overlay address ("10.28.55.42" or CIDR), or "" to leave unchanged
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

// put stores rec if it supersedes the current entry for that target (higher seq).
func (s *provStore) put(pub [32]byte, rec SignedProvision) bool {
	s.mu.Lock()
	if cur, ok := s.recs[pub]; ok && rec.Seq <= cur.Seq {
		s.mu.Unlock()
		return false
	}
	s.recs[pub] = rec
	s.mu.Unlock()
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
		if stripMask(addr) == myOverlayIP {
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
