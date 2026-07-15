package main

// approvals.go implements admission control. Once the network has an admin key,
// a newly-connecting device is NOT trusted for overlay traffic until an admin
// (with the password) signs an approval for its static key. Until then the peer
// can complete the Noise handshake and exchange control frames (so it can learn
// the admin key + its own approval), but its data packets are dropped and its
// overlay IP is not learned — it simply waits in the dashboard's pending list.
//
// Approvals are Ed25519-signed by the admin key, persisted, and gossiped exactly
// like revocations, so approving a device on one node reaches every node.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
)

// SignedApproval mirrors the admin's struct; canonicalApproval defines the bytes
// that get signed and must match byte-for-byte on both sides.
type SignedApproval struct {
	Action string `json:"action"` // "approve" | "deny"
	PubKey string `json:"pubkey"` // base64(std) of the peer's 32-byte static key
	Seq    int64  `json:"seq"`
	Ts     int64  `json:"ts"`
	Sig    string `json:"sig"`
}

func canonicalApproval(action, pubB64 string, seq, ts int64) string {
	return fmt.Sprintf("OVLYAPPROVE1|%s|%s|%d|%d", action, pubB64, seq, ts)
}

// admissionRequired reports whether admission control is active — i.e. the
// network has an admin key (so new devices must be approved).
func admissionRequired() bool {
	return adminKeySet()
}

// admitted reports whether a peer key is admin-APPROVED. This is now a purely
// informational whitelist marker (shown in the dashboard as approved/pending) —
// it does NOT gate the data plane. Blocking a device is done with Revoke, which
// tears down its session and refuses re-handshake. Without an admin key on the
// network everyone is "approved" (nothing to gate).
func admitted(pub [32]byte) bool {
	if !admissionRequired() {
		return true
	}
	if pub == gKP.pub {
		return true
	}
	return approvals.isApproved(pub)
}

func verifyApproval(rec SignedApproval) ([32]byte, bool) {
	var pub [32]byte
	if !adminKeySet() {
		return pub, false
	}
	if rec.Action != "approve" && rec.Action != "deny" {
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
	if !adminVerify([]byte(canonicalApproval(rec.Action, rec.PubKey, rec.Seq, rec.Ts)), sig) {
		return pub, false
	}
	copy(pub[:], raw)
	return pub, true
}

// --- persistent approvals store ------------------------------------------

type storedApproval struct {
	PubKey string          `json:"pubkey"`
	Action string          `json:"action"`
	Seq    int64           `json:"seq"`
	Ts     int64           `json:"ts"`
	Rec    *SignedApproval `json:"rec,omitempty"`
}

type approvalStore struct {
	mu   sync.Mutex
	recs map[[32]byte]storedApproval
	path string
}

var approvals = &approvalStore{recs: map[[32]byte]storedApproval{}}

func (s *approvalStore) isApproved(pub [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[pub]
	return ok && r.Action == "approve"
}

func (s *approvalStore) put(pub [32]byte, e storedApproval) bool {
	s.mu.Lock()
	if cur, ok := s.recs[pub]; ok && e.Seq <= cur.Seq {
		s.mu.Unlock()
		return false
	}
	s.recs[pub] = e
	s.mu.Unlock()
	s.save()
	return true
}

func (s *approvalStore) applySigned(rec SignedApproval, pub [32]byte) bool {
	r := rec
	return s.put(pub, storedApproval{PubKey: rec.PubKey, Action: rec.Action, Seq: rec.Seq, Ts: rec.Ts, Rec: &r})
}

func (s *approvalStore) list() []storedApproval {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]storedApproval, 0, len(s.recs))
	for _, r := range s.recs {
		out = append(out, r)
	}
	return out
}

func (s *approvalStore) save() {
	s.mu.Lock()
	path := s.path
	list := make([]storedApproval, 0, len(s.recs))
	for _, r := range s.recs {
		list = append(list, r)
	}
	s.mu.Unlock()
	if path == "" {
		return
	}
	if data, err := json.MarshalIndent(list, "", "  "); err == nil {
		tmp := path + ".tmp"
		if os.WriteFile(tmp, data, 0o644) == nil {
			_ = os.Rename(tmp, path)
		}
	}
}

func (s *approvalStore) load(path string) {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var list []storedApproval
	if json.Unmarshal(data, &list) != nil {
		return
	}
	n := 0
	for _, e := range list {
		if e.Rec == nil {
			continue
		}
		pub, ok := verifyApproval(*e.Rec)
		if !ok {
			continue
		}
		s.mu.Lock()
		if cur, exists := s.recs[pub]; !exists || e.Seq > cur.Seq {
			s.recs[pub] = e
		}
		s.mu.Unlock()
		n++
	}
	if n > 0 {
		log.Printf("[admission] loaded %d approval record(s) from %s", n, path)
	}
}

// buildApprovalFrame returns an "OVLYCTL1Y<json>" gossip payload.
func buildApprovalFrame(rec SignedApproval) []byte {
	b, err := json.Marshal(rec)
	if err != nil {
		return nil
	}
	out := append([]byte(nil), ctlMagic...)
	out = append(out, 'Y')
	return append(out, b...)
}

func handleApprovalGossip(payload []byte) {
	var rec SignedApproval
	if json.Unmarshal(payload, &rec) != nil {
		return
	}
	pub, ok := verifyApproval(rec)
	if !ok {
		return
	}
	approvals.applySigned(rec, pub)
}

// gossipApprovals floods every stored signed approval to peers.
func gossipApprovals() {
	if GlobalSessions == nil || GlobalConn == nil {
		return
	}
	var frames [][]byte
	for _, e := range approvals.list() {
		if e.Rec != nil {
			if f := buildApprovalFrame(*e.Rec); f != nil {
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

// selfApproved reports whether THIS node is admitted on the network (used by the
// mobile UI to show a "waiting for approval" banner).
func selfApproved() bool {
	if !admissionRequired() {
		return true
	}
	return approvals.isApproved(gKP.pub)
}
