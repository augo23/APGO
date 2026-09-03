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
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
// warnIfSelfUnapproved says so, loudly and at most once a minute, because the
// symptom otherwise looks like anything but what it is.
var (
	selfApprovalWarnMu   sync.Mutex
	selfApprovalWarnLast time.Time
)

func warnIfSelfUnapproved() {
	if selfApproved() {
		return
	}
	selfApprovalWarnMu.Lock()
	if time.Since(selfApprovalWarnLast) < time.Minute {
		selfApprovalWarnMu.Unlock()
		return
	}
	selfApprovalWarnLast = time.Now()
	selfApprovalWarnMu.Unlock()
	log.Printf("[admission] THIS DEVICE IS NOT APPROVED on this network (key %s). "+
		"Peers that enforce admission accept our control traffic — so we appear "+
		"normally in their peer list — but SILENTLY DISCARD all data: services on "+
		"those nodes will be unreachable from here while everything looks connected. "+
		"Approve this device in the admin panel.", peerKeyFingerprint(gKP.pub[:]))
}

func admissionRequired() bool {
	return adminKeySet()
}

// --- data-plane enforcement toggle ----------------------------------------

// admissionEnforced reports whether unapproved peers are actually BLOCKED, as
// opposed to merely logged.
//
// ADMISSION_ENFORCE forces the answer either way ("1"/"true"/"yes"/"on" or
// "0"/"false"/"no"/"off"). With it unset, enforcement turns itself on once the
// network is actually USING approvals — that is, once this node holds at least
// one signed approval record.
//
// THE HISTORY MATTERS, because both previous answers were wrong.
//
// It first defaulted OFF, so a staged rollout was possible: deploy warn-only,
// watch the "would drop" lines, approve what belongs, then enforce. Sound plan,
// bad default — an operator who set an admin key, watched devices land in
// "pending", and never found an obscure environment variable believed they had
// admission control and did not have it. The UI said pending; the data plane
// said welcome.
//
// So it was flipped to default ON. That broke networks, and the reason is
// worth stating plainly because it is not obvious from admitted():
//
//	admitted() is SYMMETRIC. It does not only decide whether OTHER nodes
//	accept us — it decides whether WE accept THEM. A node evaluates every
//	peer against its OWN approval store.
//
// On a network that had an admin key but had never approved anything (nothing
// forced anyone to, because enforcement was off), that store is empty
// everywhere. Turning enforcement on therefore did not gate the new device: it
// made every upgraded node reject every peer it had, in both directions, at
// once. A freshly reinstalled machine was hit hardest — its store is empty by
// definition, so it dropped all inbound data from a mesh that was perfectly
// willing to talk to it, and presented as 100% packet loss to every peer while
// showing them all as connected.
//
// Approving that one device does not help, either: it fixes what peers think
// of IT, and does nothing about what it thinks of THEM.
//
// The rule below keeps the gate closed by default without applying it
// retroactively to networks that never opted in. Zero approval records means
// approvals have never been issued here, so enforcing is a change nobody asked
// for; one approval record means an admin has started using the feature, and
// from then on it is enforced properly. A brand-new network crosses that line
// the moment its first device is approved.
//
// The trade-off, stated honestly: between adopting an admin key and issuing
// the first approval, this node does not block unapproved peers. That window
// is the price of not disconnecting existing fleets on upgrade, and it closes
// permanently with the first approval. ADMISSION_ENFORCE=1 removes the window
// for anyone who wants strict behaviour from the first packet.
//
// Networks with NO admin key are unaffected either way: admissionRequired() is
// false, so admitted() returns true for everyone and none of this engages.
var (
	admissionEnvOnce sync.Once
	// admissionEnvForce is nil when ADMISSION_ENFORCE is unset/unparseable.
	admissionEnvForce *bool
	// admissionEnforceLogged makes the state change log once, not per packet.
	admissionEnforceLogged atomic.Bool
)

func admissionEnvOverride() *bool {
	admissionEnvOnce.Do(func() {
		switch strings.ToLower(strings.TrimSpace(os.Getenv("ADMISSION_ENFORCE"))) {
		case "1", "true", "yes", "on":
			v := true
			admissionEnvForce = &v
		case "0", "false", "no", "off":
			v := false
			admissionEnvForce = &v
		}
	})
	return admissionEnvForce
}

// admissionEnforced is evaluated LIVE, not memoised at startup. The approval
// store is filled by mesh gossip seconds after the process starts, so a value
// computed once at boot would freeze this node in the state it happened to
// have before its first peer connected — which is exactly the empty-store case
// this logic exists to handle.
func admissionEnforced() bool {
	if o := admissionEnvOverride(); o != nil {
		if *o && admissionRequired() && admissionEnforceLogged.CompareAndSwap(false, true) {
			log.Printf("[admission] ENFORCING (ADMISSION_ENFORCE=1) — unapproved peers cannot pass data")
		}
		return *o
	}
	if !admissionRequired() {
		return false // no admin key — nothing to gate
	}
	if !approvals.hasAnyApproval() {
		// Approvals have never been issued on this network. Do not retro-fit a
		// gate onto a fleet that never had one; say so, once, so the state is
		// discoverable rather than mysterious.
		if admissionEnforceLogged.CompareAndSwap(false, true) {
			log.Printf("[admission] NOT enforcing: this network has an admin key but no approval " +
				"records yet, so blocking unapproved peers would disconnect every node at once. " +
				"Approve one device (any dashboard, or the phone apps) and enforcement turns on " +
				"automatically from then on. ADMISSION_ENFORCE=1 forces it on now.")
		}
		return false
	}
	if admissionEnforceLogged.CompareAndSwap(false, true) {
		log.Printf("[admission] ENFORCING — unapproved peers cannot pass overlay data, " +
			"advertise as exits, inject peer endpoints, or appear in the roster")
	}
	return true
}

// admissionLogEvery throttles the per-peer message. Without it an unapproved
// peer logs on every single packet and buries everything else.
const admissionLogEvery = 30 * time.Second

var (
	admissionLogMu   sync.Mutex
	admissionLogSeen = map[[32]byte]time.Time{}
)

// admissionOK is THE data-plane gate — every enforcement point calls this, not
// admitted(). It returns whether the peer's traffic may pass; in warn-only mode
// it returns true while logging what enforcement would have dropped.
//
// admitted() stays the pure predicate on purpose: the dashboard's
// approved/pending badge must keep showing real approval state regardless of
// whether enforcement is switched on.
//
// where is a short label ("ingress", "relay-in", "egress", …) so the log says
// which path a peer is being blocked on.
func admissionOK(pub [32]byte, where string) bool {
	if admitted(pub) {
		return true
	}
	enforcing := admissionEnforced()
	admissionLogMu.Lock()
	last, seen := admissionLogSeen[pub]
	fresh := !seen || time.Since(last) > admissionLogEvery
	if fresh {
		admissionLogSeen[pub] = time.Now()
	}
	admissionLogMu.Unlock()
	if fresh {
		if enforcing {
			log.Printf("[admission] DROP %s from unapproved peer %s", where, peerKeyFingerprint(pub[:]))
		} else {
			log.Printf("[admission] would drop %s from unapproved peer %s (set ADMISSION_ENFORCE=1 to enforce)", where, peerKeyFingerprint(pub[:]))
		}
	}
	return !enforcing
}

// admitted reports whether a peer key is admin-APPROVED, and it DOES gate the
// data plane again.
//
// History, because this flipped twice: it originally gated data, was then
// downgraded to a purely informational dashboard marker with blocking left to
// Revoke, and is now enforcing once more. The informational version had a
// surprising consequence — a device sitting in the "pending" list had full
// overlay access, and could reach every other node through any admitted node's
// relay paths, because the relay handlers checked revocation but not approval.
// Pending looked like a gate and was not one.
//
// Enforcement points (mirrored in ios/core):
//   - ingress data path, after control-frame dispatch
//   - case 'R' relay handler, on both the requesting and forwarding sessions
//   - the return-path relay in the decrypt loop
//   - egress unicast and the discovery flood
//   - case 'A', which no longer learns an unapproved peer's overlay IP
//
// Control frames stay EXEMPT everywhere: an unapproved peer must be able to
// exchange them or it can never learn the admin key and its own approval, and
// approval would be unreachable by design.
//
// Revoke remains the stronger action — it tears down the session and refuses
// re-handshake, whereas an unapproved peer may still hold a session and talk
// control frames. Without an admin key on the network everyone is "approved"
// (admissionRequired() is false), so none of this affects a deployment that
// never opted in.
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

// hasAnyApproval reports whether ANY device has been approved on this network.
// It is the signal that an admin has actually started using admission control,
// which is what admissionEnforced() keys enforcement off — see the long note
// there for why "has an admin key" was not a safe enough signal on its own.
func (s *approvalStore) hasAnyApproval() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.recs {
		if r.Action == "approve" {
			return true
		}
	}
	return false
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
