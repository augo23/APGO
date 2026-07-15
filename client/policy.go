package main

// policy.go carries admin-signed policy that nodes apply live (no restart).
// Today it toggles the optional post-quantum layer, PER NODE: an admin signs a
// policy targeting a specific node's static key (or "" for the whole network),
// and it floods the mesh. A node applies the policy that targets it (or the
// network-wide one), latest epoch wins. Every node also advertises its live PQ
// state to peers (frame 'p') so any admin panel can show a per-node checkbox.
//
// Signed by the admin Ed25519 key, gossiped, persisted, epoch-superseded.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
)

type SignedPolicy struct {
	PubKey      string `json:"pubkey"` // "" = network-wide; else base64 target static key
	PostQuantum bool   `json:"post_quantum"`
	Epoch       int64  `json:"epoch"`
	Ts          int64  `json:"ts"`
	Sig         string `json:"sig"`
}

func canonicalPolicy(pubB64 string, pq bool, epoch, ts int64) string {
	return fmt.Sprintf("OVLYPOLICY1|%s|%t|%d|%d", pubB64, pq, epoch, ts)
}

var (
	policyMu           sync.Mutex
	nodePolicies       = map[string]SignedPolicy{} // key: PubKey ("" = network-wide)
	currentPolicyEpoch int64                        // epoch of the policy applied to THIS node
)

func policyFilePath() string {
	if p := os.Getenv("POLICY_FILE"); p != "" {
		return p
	}
	return "/state/policy.json"
}

// selfPubB64 is this node's base64 static key, or "" before the key is loaded.
func selfPubB64() string {
	var zero [32]byte
	if gKP.pub == zero {
		return ""
	}
	return base64.StdEncoding.EncodeToString(gKP.pub[:])
}

// applyPolicyFile loads persisted policies at startup and applies whatever
// targets this node (network-wide entries apply even before the key is loaded).
func applyPolicyFile() {
	data, err := os.ReadFile(policyFilePath())
	if err != nil {
		return
	}
	var list []SignedPolicy
	if json.Unmarshal(data, &list) != nil {
		// Back-compat: an older single-object policy file.
		var one SignedPolicy
		if json.Unmarshal(data, &one) == nil && one.Sig != "" {
			list = []SignedPolicy{one}
		}
	}
	policyMu.Lock()
	for _, p := range list {
		if cur, ok := nodePolicies[p.PubKey]; !ok || p.Epoch > cur.Epoch {
			nodePolicies[p.PubKey] = p
		}
	}
	policyMu.Unlock()
	recomputeSelfPolicy()
}

// recomputeSelfPolicy picks the newest policy that applies to this node
// (network-wide or targeting our key) and sets pqEnabled accordingly.
func recomputeSelfPolicy() {
	self := selfPubB64()
	policyMu.Lock()
	cands := []SignedPolicy{}
	if p, ok := nodePolicies[""]; ok {
		cands = append(cands, p)
	}
	if self != "" {
		if p, ok := nodePolicies[self]; ok {
			cands = append(cands, p)
		}
	}
	policyMu.Unlock()
	best := SignedPolicy{Epoch: -1}
	found := false
	for _, p := range cands {
		if p.Epoch > best.Epoch {
			best = p
			found = true
		}
	}
	if found && best.Epoch > currentPolicyEpoch {
		pqEnabled = best.PostQuantum
		currentPolicyEpoch = best.Epoch
		target := "network-wide"
		if best.PubKey != "" {
			target = "this node"
		}
		log.Printf("[policy] applied %s policy (epoch %d): post_quantum=%v", target, best.Epoch, best.PostQuantum)
	}
}

func verifyPolicy(p SignedPolicy) bool {
	if !adminKeySet() {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(p.Sig)
	if err != nil {
		return false
	}
	return adminVerify([]byte(canonicalPolicy(p.PubKey, p.PostQuantum, p.Epoch, p.Ts)), sig)
}

func buildPolicyFrame(p SignedPolicy) []byte {
	b, err := json.Marshal(p)
	if err != nil {
		return nil
	}
	out := append([]byte(nil), ctlMagic...)
	out = append(out, 'D')
	return append(out, b...)
}

func savePolicies() {
	policyMu.Lock()
	list := make([]SignedPolicy, 0, len(nodePolicies))
	for _, p := range nodePolicies {
		list = append(list, p)
	}
	policyMu.Unlock()
	if data, err := json.MarshalIndent(list, "", "  "); err == nil {
		tmp := policyFilePath() + ".tmp"
		if os.WriteFile(tmp, data, 0o600) == nil {
			_ = os.Rename(tmp, policyFilePath())
		}
	}
}

// adoptPolicy verifies + stores a newer policy, applies it to us if it targets
// us, persists, and re-floods it.
func adoptPolicy(p SignedPolicy) {
	if !verifyPolicy(p) {
		return
	}
	policyMu.Lock()
	if cur, ok := nodePolicies[p.PubKey]; ok && p.Epoch <= cur.Epoch {
		policyMu.Unlock()
		return
	}
	nodePolicies[p.PubKey] = p
	policyMu.Unlock()
	savePolicies()
	recomputeSelfPolicy()

	if f := buildPolicyFrame(p); f != nil && GlobalSessions != nil && GlobalConn != nil {
		for _, addr := range GlobalSessions.EstablishedAddrs() {
			if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
				_ = sendPacket(GlobalConn, addr, s, f)
			}
		}
	}
}

func handlePolicyGossip(payload []byte) {
	var p SignedPolicy
	if json.Unmarshal(payload, &p) != nil {
		return
	}
	adoptPolicy(p)
}

// gossipPolicy re-floods every stored policy so nodes that just came online
// (and nodes that are the target of a policy but weren't reachable yet) converge.
func gossipPolicy() {
	if GlobalSessions == nil || GlobalConn == nil {
		return
	}
	policyMu.Lock()
	frames := make([][]byte, 0, len(nodePolicies))
	for _, p := range nodePolicies {
		if f := buildPolicyFrame(p); f != nil {
			frames = append(frames, f)
		}
	}
	policyMu.Unlock()
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

// --- live PQ-state advertisement (frame 'p') -----------------------------

var (
	peerPQMu sync.Mutex
	peerPQ   = map[[32]byte]bool{}
)

func setPeerPQ(pub [32]byte, on bool) {
	peerPQMu.Lock()
	peerPQ[pub] = on
	peerPQMu.Unlock()
}

func peerPQByPub(pub [32]byte) bool {
	peerPQMu.Lock()
	defer peerPQMu.Unlock()
	return peerPQ[pub]
}

// forgetPeerPQStatus drops the cached advertised-PQ flag for a peer when its
// last route is gone, so a reconnecting peer's PQ state is shown fresh (and
// re-learned from its next status frame) rather than lingering stale.
func forgetPeerPQStatus(pub [32]byte) {
	peerPQMu.Lock()
	delete(peerPQ, pub)
	peerPQMu.Unlock()
}

// buildPQStatus advertises this node's live post-quantum state to peers.
func buildPQStatus() []byte {
	out := append([]byte(nil), ctlMagic...)
	out = append(out, 'p')
	b := byte(0)
	if pqEnabled {
		b = 1
	}
	return append(out, b)
}
