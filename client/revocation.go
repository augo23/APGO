package main

// revocation.go handles both kinds of revocation and keeps them in one
// persistent, listable store:
//
//   - signed   — an admin-signed record (Ed25519, verified against the network
//                admin public key). Trustworthy across the network, gossip-ready.
//   - local    — an unsigned kick that applies only to THIS node (used when no
//                admin key has been set up yet).
//
// Either way a revoked peer shows up in the dashboard's "Revoked peers" list
// and can be re-admitted ("Accept"): a signed entry needs a signed restore,
// a local entry is simply removed.

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

// SignedRevocation mirrors the admin's struct; the signed bytes are defined by
// canonicalRevocation and must match the admin byte-for-byte.
type SignedRevocation struct {
	Action string `json:"action"` // "revoke" | "restore"
	PubKey string `json:"pubkey"` // base64(std) of the peer's 32-byte X25519 static key
	Seq    int64  `json:"seq"`
	Ts     int64  `json:"ts"`
	Sig    string `json:"sig"` // base64(std) Ed25519 signature
}

func canonicalRevocation(action, pubB64 string, seq, ts int64) string {
	return fmt.Sprintf("OVLYREVOKE1|%s|%s|%d|%d", action, pubB64, seq, ts)
}

// adminPub is the trusted admin ML-DSA (post-quantum) public key, held as its
// marshaled bytes. Empty disables signed records on this node (they're ignored;
// local kicks still work). Parsing + verification go through adminsig.go.
var adminPub []byte

// adminPubFile persists a trust-on-first-use admin key seeded from a peer, so it
// survives restarts. Empty disables persistence. Set from ADMIN_PUBKEY_FILE.
var adminPubFile string

func loadAdminPublicKey() {
	adminPubFile = os.Getenv("ADMIN_PUBKEY_FILE")

	// Explicit config always wins and is never overridden by a seed.
	if v := os.Getenv("ADMIN_PUBLIC_KEY"); v != "" {
		if raw, err := base64.StdEncoding.DecodeString(v); err == nil && setAdminPubBytes(raw) {
			log.Printf("[revocation] admin public key loaded from env — signed records enabled")
			return
		}
		log.Printf("[revocation] ADMIN_PUBLIC_KEY is not a valid base64 ML-DSA key; ignoring")
	}

	// Otherwise fall back to a previously-seeded key on disk (TOFU).
	if adminPubFile != "" {
		if data, err := os.ReadFile(adminPubFile); err == nil {
			if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data))); err == nil && setAdminPubBytes(raw) {
				log.Printf("[revocation] admin public key loaded (previously seeded)")
			}
		}
	}
}

// setAdminPub sets the trusted admin key, optionally persisting it to disk.
func setAdminPub(raw []byte, persist bool) {
	if !setAdminPubBytes(raw) {
		return
	}
	if persist && adminPubFile != "" {
		_ = os.WriteFile(adminPubFile, []byte(base64.StdEncoding.EncodeToString(raw)), 0o644)
	}
}

// adoptSeededAdminPub implements trust-on-first-use: if this node has no admin
// key yet, adopt the one a peer seeded, persist it, and re-check stored
// revocations against it. Once set (by config or an earlier seed) it is locked.
func adoptSeededAdminPub(b64, source string) {
	if adminKeySet() {
		return // already trust a key — first-seed / config wins
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || !adminPubValid(raw) {
		return
	}
	setAdminPub(raw, true)
	log.Printf("[revocation] adopted seeded admin public key %s from peer %s (trust-on-first-use)", peerKeyFingerprint(raw), source)
	if rf := os.Getenv("REVOCATIONS_FILE"); rf != "" {
		revocations.load(rf) // re-verify any persisted records now that we trust a key
	}
}

// buildAdminSeed returns an "OVLYCTL1P<base64 pubkey>" control payload that
// advertises this node's trusted admin key to peers, or nil if there is none.
func buildAdminSeed() []byte {
	if !adminKeySet() {
		return nil
	}
	out := append([]byte(nil), ctlMagic...)
	out = append(out, 'P')
	return append(out, []byte(base64.StdEncoding.EncodeToString(adminPub))...)
}

// verifyRevocation checks the signature against adminPub and returns the target
// 32-byte X25519 key on success.
func verifyRevocation(rec SignedRevocation) ([32]byte, bool) {
	var pub [32]byte
	if !adminKeySet() {
		return pub, false
	}
	if rec.Action != "revoke" && rec.Action != "restore" {
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
	if !adminVerify([]byte(canonicalRevocation(rec.Action, rec.PubKey, rec.Seq, rec.Ts)), sig) {
		return pub, false
	}
	copy(pub[:], raw)
	return pub, true
}

// --- persistent revocation store -----------------------------------------

// storedRev is one persisted entry — signed (network) or local (this node).
type storedRev struct {
	PubKey string            `json:"pubkey"` // base64(std) of the 32-byte peer key
	Action string            `json:"action"` // "revoke" | "restore"
	Seq    int64             `json:"seq"`
	Ts     int64             `json:"ts"`
	Signed bool              `json:"signed"`
	Rec    *SignedRevocation `json:"rec,omitempty"` // present iff Signed (for re-verify + gossip)
}

type revStore struct {
	mu   sync.Mutex
	recs map[[32]byte]storedRev
	path string
}

var revocations = &revStore{recs: map[[32]byte]storedRev{}}

func (s *revStore) isRevoked(pub [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[pub]
	return ok && r.Action == "revoke"
}

// revokedIPs is a data-plane block list of overlay IPs belonging to revoked
// keys. The handshake gate stops a revoked peer from (re)connecting, but an
// existing or RELAYED path could still carry packets to it; egress and relay
// consult this set and drop such traffic so a revoked node is fully cut off
// (you can't even ping it). Populated whenever a key is revoked/restored.
var (
	revokedIPMu   sync.RWMutex
	revokedIPSet  = map[string]bool{}
	revokedIPByKey = map[[32]byte]string{}
)

// setKeyRevoked blocks/unblocks a peer's overlay IP at the data plane, keyed by
// the peer's static key. Keying by key (not IP) guarantees a re-admit clears the
// exact IP that was blocked, even if the IP mapping changed or is unknown now.
func setKeyRevoked(pub [32]byte, revoked bool) {
	revokedIPMu.Lock()
	defer revokedIPMu.Unlock()
	if revoked {
		if ip := resolvePeerIP(pub); ip != "" {
			revokedIPByKey[pub] = ip
			revokedIPSet[ip] = true
		}
	} else if ip, ok := revokedIPByKey[pub]; ok {
		delete(revokedIPSet, ip)
		delete(revokedIPByKey, pub)
	}
}

// isOverlayIPRevoked reports whether an overlay IP belongs to a revoked key.
func isOverlayIPRevoked(ip string) bool {
	if ip == "" {
		return false
	}
	revokedIPMu.RLock()
	defer revokedIPMu.RUnlock()
	return revokedIPSet[ip]
}

// put stores an entry if it supersedes existing state. Signed entries always
// win over local ones; between the same kind, a higher seq wins.
func (s *revStore) put(pub [32]byte, e storedRev) (changed, nowRevoked bool) {
	s.mu.Lock()
	if cur, ok := s.recs[pub]; ok {
		if cur.Signed && !e.Signed {
			s.mu.Unlock()
			return false, cur.Action == "revoke"
		}
		if cur.Signed == e.Signed && e.Seq <= cur.Seq {
			s.mu.Unlock()
			return false, cur.Action == "revoke"
		}
	}
	s.recs[pub] = e
	s.mu.Unlock()
	s.save()
	// Keep the data-plane IP block in sync: block on revoke, UNBLOCK on restore
	// (so a re-admitted node is reachable again — including over relay paths).
	setKeyRevoked(pub, e.Action == "revoke")
	return true, e.Action == "revoke"
}

// applySigned records a verified admin-signed revoke/restore.
func (s *revStore) applySigned(rec SignedRevocation, pub [32]byte) (changed, nowRevoked bool) {
	r := rec
	return s.put(pub, storedRev{
		PubKey: rec.PubKey, Action: rec.Action, Seq: rec.Seq, Ts: rec.Ts, Signed: true, Rec: &r,
	})
}

// applyLocal records an unsigned, this-node-only revoke/restore.
func (s *revStore) applyLocal(pub [32]byte, action string) (changed, nowRevoked bool) {
	now := time.Now()
	return s.put(pub, storedRev{
		PubKey: base64.StdEncoding.EncodeToString(pub[:]),
		Action: action, Seq: now.UnixNano(), Ts: now.Unix(), Signed: false,
	})
}

// removeLocal deletes an unsigned entry (the "Accept" action for a local
// revocation). Signed entries are unaffected — those need a signed restore.
func (s *revStore) removeLocal(pub [32]byte) bool {
	s.mu.Lock()
	cur, ok := s.recs[pub]
	if !ok || cur.Signed {
		s.mu.Unlock()
		return false
	}
	delete(s.recs, pub)
	s.mu.Unlock()
	s.save()
	// Local "Accept" — unblock the peer's overlay IP so it's reachable again.
	setKeyRevoked(pub, false)
	return true
}

func (s *revStore) list() []storedRev {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]storedRev, 0, len(s.recs))
	for _, r := range s.recs {
		out = append(out, r)
	}
	return out
}

func (s *revStore) save() {
	s.mu.Lock()
	path := s.path
	list := make([]storedRev, 0, len(s.recs))
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

// load reads persisted entries. Signed entries are re-verified against adminPub
// (tamper-evident); local entries are trusted as this node's own on-disk state.
func (s *revStore) load(path string) {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var list []storedRev
	if json.Unmarshal(data, &list) != nil {
		return
	}
	n := 0
	for _, e := range list {
		var pub [32]byte
		if e.Signed {
			if e.Rec == nil {
				continue
			}
			p, ok := verifyRevocation(*e.Rec)
			if !ok {
				continue
			}
			pub = p
		} else {
			raw, err := base64.StdEncoding.DecodeString(e.PubKey)
			if err != nil || len(raw) != 32 {
				continue
			}
			copy(pub[:], raw)
		}
		s.mu.Lock()
		if cur, exists := s.recs[pub]; !exists || (e.Signed && !cur.Signed) || (e.Signed == cur.Signed && e.Seq > cur.Seq) {
			s.recs[pub] = e
		}
		s.mu.Unlock()
		n++
	}
	if n > 0 {
		log.Printf("[revocation] loaded %d record(s) from %s", n, path)
	}
}

// buildRevocationFrame returns an "OVLYCTL1W<json>" gossip payload carrying a
// signed revoke/restore so it can flood the mesh.
func buildRevocationFrame(rec SignedRevocation) []byte {
	b, err := json.Marshal(rec)
	if err != nil {
		return nil
	}
	out := append([]byte(nil), ctlMagic...)
	out = append(out, 'W')
	return append(out, b...)
}

// handleRevocationGossip verifies a gossiped signed revocation and applies it
// (seq-deduped in the store), tearing down the session if it's a revoke.
func handleRevocationGossip(payload []byte) {
	var rec SignedRevocation
	if json.Unmarshal(payload, &rec) != nil {
		return
	}
	pub, ok := verifyRevocation(rec)
	if !ok {
		return
	}
	_, nowRevoked := revocations.applySigned(rec, pub)
	if nowRevoked && GlobalSessions != nil {
		GlobalSessions.RevokeByKey(pub)
	}
}

// gossipRevocations broadcasts every stored SIGNED revoke/restore to peers so a
// revocation applied on one node reaches (and is enforced + shown on) all nodes.
func gossipRevocations() {
	if GlobalSessions == nil || GlobalConn == nil {
		return
	}
	var frames [][]byte
	for _, e := range revocations.list() {
		if e.Signed && e.Rec != nil {
			if f := buildRevocationFrame(*e.Rec); f != nil {
				frames = append(frames, f)
			}
		}
	}
	if len(frames) == 0 {
		return
	}
	for _, addr := range GlobalSessions.EstablishedAddrs() {
		s := GlobalSessions.GetByAddr(addr)
		if s == nil || !s.Established() {
			continue
		}
		for _, f := range frames {
			_ = sendPacket(GlobalConn, addr, s, f)
		}
	}
}

// RevokeByKey tears down every live session whose peer static key matches pub,
// forgetting its overlay-IP mappings. Used when a revocation is applied.
func (t *SessionTable) RevokeByKey(pub [32]byte) int {
	t.mu.Lock()
	var lost []*net.UDPAddr
	for k, s := range t.byAddr {
		if s.peerStatic == pub {
			delete(t.byAddr, k)
			if s.addr != nil {
				lost = append(lost, s.addr)
			}
		}
	}
	cb := t.onSessionLost
	t.mu.Unlock()
	// Block this peer's overlay IP at the data plane too (covers relayed paths).
	setKeyRevoked(pub, true)
	for _, a := range lost {
		ipLearning.ForgetAddr(a)
		if cb != nil {
			go cb(a)
		}
	}
	return len(lost)
}
