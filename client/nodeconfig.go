package main

// nodeconfig.go carries admin-signed, per-node runtime configuration that a
// node applies live: DHT participation, use of public relays, whether it IS a
// public relay (and on what bandwidth budget), whether it is a VPN exit node
// (and on what bandwidth budget), and the static relay list.
//
// WHY THIS EXISTS AT ALL
//
// These settings were reachable only two ways: editing YAML on the node, or
// POSTing /api/discovery to that node's OWN control port. Both require standing
// on the machine. The two node types that most need these settings -- a
// container, and a phone -- are exactly the two with no YAML to edit and no
// reachable control port. So an admin could see every node in the dashboard and
// configure none of them.
//
// The model is copied deliberately from policy.go, which already solved the
// same problem for the post-quantum toggle: an admin Ed25519 signature over a
// canonical string, gossiped to the whole mesh, persisted, and superseded by
// epoch. Nodes apply the record that targets them. PubKey "" means network-wide,
// so one type covers "every node" and "this node" without a second mechanism.
//
// Pointer fields are load-bearing. A nil field means UNCHANGED, which is not the
// same as false: without that distinction, saving the DHT toggle from one panel
// would silently switch off an exit node configured from another. Every setter
// therefore sends only what it means to change.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
)

type SignedNodeConfig struct {
	PubKey string `json:"pubkey"` // "" = network-wide; else base64 target static key

	DHT         *bool `json:"dht,omitempty"`
	UseRelays   *bool `json:"use_public_relays,omitempty"`
	PublicRelay *bool `json:"public_relay,omitempty"`
	ExitNode    *bool `json:"exit_node,omitempty"`

	// Trackers is the public BitTorrent tracker list this node announces to in
	// order to find peers (trackers.go). TrackersOn turns that discovery method
	// off without discarding the list, so it can be switched back on later
	// without retyping it.
	Trackers   *[]string `json:"trackers,omitempty"`
	TrackersOn *bool     `json:"trackers_on,omitempty"`

	// Rendezvous is the ONE server this node uses for coordinated discovery,
	// with optional credentials ("user:pass" = HTTP Basic, bare = Bearer,
	// "" = none). Singular by design: a rendezvous server is an authority a
	// node trusts to introduce it to the mesh, and a list of several is a list
	// of several things that can lie to it. If it is unreachable the node
	// falls back to the DHT and trackers, which is the redundancy that
	// matters.
	Rendezvous     *string `json:"rendezvous,omitempty"`
	RendezvousAuth *string `json:"rendezvous_auth,omitempty"`

	// Bandwidth budgets, in BYTES PER SECOND (and bytes for the quotas), already
	// parsed. The wire format carries numbers rather than "5mbit" so that every
	// node agrees on the value without re-running a string parser -- and so the
	// signature covers the number that is actually enforced.
	RelayUp    *int64 `json:"relay_up_bps,omitempty"`
	RelayDown  *int64 `json:"relay_down_bps,omitempty"`
	RelayQuota *int64 `json:"relay_quota_bytes,omitempty"`
	ExitUp     *int64 `json:"exit_up_bps,omitempty"`
	ExitDown   *int64 `json:"exit_down_bps,omitempty"`
	ExitQuota  *int64 `json:"exit_quota_bytes,omitempty"`

	Epoch int64  `json:"epoch"`
	Ts    int64  `json:"ts"`
	Sig   string `json:"sig"`
}

// canonicalNodeConfig is the exact byte string the admin key signs.
//
// Two properties matter and both are easy to get wrong. First, every field is
// included -- a field outside the signature is a field an attacker can rewrite
// in flight, and "relay bandwidth limit" is precisely the field someone would
// want to rewrite. Second, it is DETERMINISTIC: absent fields render as "-"
// rather than being skipped, so "DHT unset" and "DHT false" cannot collide into
// the same signed string, and the relay list is joined in the order given after
// being sorted by the caller.
func canonicalNodeConfig(c SignedNodeConfig) string {
	b := func(p *bool) string {
		if p == nil {
			return "-"
		}
		return fmt.Sprintf("%t", *p)
	}
	i := func(p *int64) string {
		if p == nil {
			return "-"
		}
		return fmt.Sprintf("%d", *p)
	}
	str := func(p *string) string {
		if p == nil {
			return "-"
		}
		return *p
	}
	trackers := "-"
	if c.Trackers != nil {
		trackers = strings.Join(*c.Trackers, ",")
	}
	return fmt.Sprintf("OVLYNODECFG1|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%d|%d",
		c.PubKey, b(c.DHT), b(c.UseRelays), b(c.PublicRelay), b(c.ExitNode),
		trackers, b(c.TrackersOn), str(c.Rendezvous), str(c.RendezvousAuth),
		i(c.RelayUp), i(c.RelayDown), i(c.RelayQuota),
		i(c.ExitUp), i(c.ExitDown), i(c.ExitQuota),
		c.Epoch, c.Ts)
}

var (
	nodeCfgMu       sync.Mutex
	nodeConfigs     = map[string]SignedNodeConfig{} // key: PubKey ("" = network-wide)
	appliedCfgEpoch int64
)

func nodeConfigFilePath() string {
	if p := os.Getenv("NODE_CONFIG_FILE"); p != "" {
		return p
	}
	return "/state/nodeconfig.json"
}

func verifyNodeConfig(c SignedNodeConfig) bool {
	if !adminKeySet() {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(c.Sig)
	if err != nil {
		return false
	}
	return adminVerify([]byte(canonicalNodeConfig(c)), sig)
}

func buildNodeConfigFrame(c SignedNodeConfig) []byte {
	b, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	out := append([]byte(nil), ctlMagic...)
	out = append(out, 'F')
	return append(out, b...)
}

func saveNodeConfigs() {
	nodeCfgMu.Lock()
	list := make([]SignedNodeConfig, 0, len(nodeConfigs))
	for _, c := range nodeConfigs {
		list = append(list, c)
	}
	nodeCfgMu.Unlock()
	sort.Slice(list, func(a, b int) bool { return list[a].PubKey < list[b].PubKey })
	if data, err := json.MarshalIndent(list, "", "  "); err == nil {
		tmp := nodeConfigFilePath() + ".tmp"
		if os.WriteFile(tmp, data, 0o600) == nil {
			_ = os.Rename(tmp, nodeConfigFilePath())
		}
	}
}

// loadNodeConfigs restores persisted records at startup and applies whatever
// targets this node. Called before the transport starts, so a node that reboots
// keeps the configuration an admin gave it even if no peer is reachable yet --
// otherwise a relay would silently revert to "not a relay" on every restart
// until the mesh re-gossiped, which is the kind of gap nobody notices until the
// relay is needed.
func loadNodeConfigs() {
	data, err := os.ReadFile(nodeConfigFilePath())
	if err != nil {
		return
	}
	var list []SignedNodeConfig
	if json.Unmarshal(data, &list) != nil {
		return
	}
	nodeCfgMu.Lock()
	for _, c := range list {
		if cur, ok := nodeConfigs[c.PubKey]; !ok || c.Epoch > cur.Epoch {
			nodeConfigs[c.PubKey] = c
		}
	}
	nodeCfgMu.Unlock()
	recomputeSelfNodeConfig()
}

// effectiveNodeConfig merges the network-wide record with the one targeting
// this node. Per-node wins field by field, so a network-wide default ("everyone
// uses relays") can stand while one node overrides a single setting, without
// that node's record having to restate every other value.
func effectiveNodeConfig(self string) SignedNodeConfig {
	nodeCfgMu.Lock()
	wide, hasWide := nodeConfigs[""]
	mine, hasMine := nodeConfigs[self]
	nodeCfgMu.Unlock()

	out := SignedNodeConfig{}
	if hasWide {
		out = wide
	}
	if hasMine && self != "" {
		if mine.DHT != nil {
			out.DHT = mine.DHT
		}
		if mine.UseRelays != nil {
			out.UseRelays = mine.UseRelays
		}
		if mine.PublicRelay != nil {
			out.PublicRelay = mine.PublicRelay
		}
		if mine.ExitNode != nil {
			out.ExitNode = mine.ExitNode
		}
		if mine.Trackers != nil {
			out.Trackers = mine.Trackers
		}
		if mine.TrackersOn != nil {
			out.TrackersOn = mine.TrackersOn
		}
		if mine.Rendezvous != nil {
			out.Rendezvous = mine.Rendezvous
		}
		if mine.RendezvousAuth != nil {
			out.RendezvousAuth = mine.RendezvousAuth
		}
		if mine.RelayUp != nil {
			out.RelayUp = mine.RelayUp
		}
		if mine.RelayDown != nil {
			out.RelayDown = mine.RelayDown
		}
		if mine.RelayQuota != nil {
			out.RelayQuota = mine.RelayQuota
		}
		if mine.ExitUp != nil {
			out.ExitUp = mine.ExitUp
		}
		if mine.ExitDown != nil {
			out.ExitDown = mine.ExitDown
		}
		if mine.ExitQuota != nil {
			out.ExitQuota = mine.ExitQuota
		}
		if mine.Epoch > out.Epoch {
			out.Epoch = mine.Epoch
		}
	}
	return out
}

// adoptNodeConfig verifies, stores, applies and re-floods a record.
func adoptNodeConfig(c SignedNodeConfig) {
	if !verifyNodeConfig(c) {
		return
	}
	nodeCfgMu.Lock()
	if cur, ok := nodeConfigs[c.PubKey]; ok && c.Epoch <= cur.Epoch {
		nodeCfgMu.Unlock()
		return
	}
	nodeConfigs[c.PubKey] = c
	nodeCfgMu.Unlock()
	saveNodeConfigs()
	recomputeSelfNodeConfig()

	if f := buildNodeConfigFrame(c); f != nil && GlobalSessions != nil && GlobalConn != nil {
		for _, addr := range GlobalSessions.EstablishedAddrs() {
			if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
				_ = sendPacket(GlobalConn, addr, s, f)
			}
		}
	}
}

func handleNodeConfigGossip(payload []byte) {
	var c SignedNodeConfig
	if json.Unmarshal(payload, &c) != nil {
		return
	}
	adoptNodeConfig(c)
}

// gossipNodeConfigs re-floods every stored record, so a node that was offline
// when it was configured converges once it returns.
func gossipNodeConfigs() {
	if GlobalSessions == nil || GlobalConn == nil {
		return
	}
	nodeCfgMu.Lock()
	frames := make([][]byte, 0, len(nodeConfigs))
	for _, c := range nodeConfigs {
		if f := buildNodeConfigFrame(c); f != nil {
			frames = append(frames, f)
		}
	}
	nodeCfgMu.Unlock()
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

// nodeConfigSnapshot reports what an admin panel should display for a target
// key: the merged effective values plus which record supplied them.
func nodeConfigSnapshot(pubB64 string) map[string]any {
	eff := effectiveNodeConfig(pubB64)
	nodeCfgMu.Lock()
	_, hasOwn := nodeConfigs[pubB64]
	_, hasWide := nodeConfigs[""]
	nodeCfgMu.Unlock()
	// Trackers fall back to what this node is ACTUALLY using when no signed
	// record has set them, so the panel shows the live list rather than an
	// empty box -- which is what made "copy from this node" report that a node
	// with eight trackers had none.
	trackers := []string{}
	if eff.Trackers != nil {
		trackers = *eff.Trackers
	} else if pubB64 == selfPubB64() {
		trackers = currentTrackers()
	}
	deref := func(p *bool) bool { return p != nil && *p }
	derefS := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	derefI := func(p *int64) int64 {
		if p == nil {
			return 0
		}
		return *p
	}
	return map[string]any{
		"pubkey":            pubB64,
		"has_node_record":   hasOwn,
		"has_network_wide":  hasWide,
		"epoch":             eff.Epoch,
		"dht":               deref(eff.DHT),
		"use_public_relays": deref(eff.UseRelays),
		"public_relay":      deref(eff.PublicRelay),
		"exit_node":         deref(eff.ExitNode),
		"trackers":          trackers,
		"trackers_on":       eff.TrackersOn == nil || *eff.TrackersOn,
		"rendezvous":        derefS(eff.Rendezvous),
		"rendezvous_auth":   derefS(eff.RendezvousAuth),
		"relay_up_bps":      derefI(eff.RelayUp),
		"relay_down_bps":    derefI(eff.RelayDown),
		"relay_quota_bytes": derefI(eff.RelayQuota),
		"exit_up_bps":       derefI(eff.ExitUp),
		"exit_down_bps":     derefI(eff.ExitDown),
		"exit_quota_bytes":  derefI(eff.ExitQuota),
	}
}

var _ = log.Printf

// --- applying a record to the live node -------------------------------------

// recomputeSelfNodeConfig applies the merged record for THIS node. Called at
// startup, on every adopted gossip frame, and after a local API change.
//
// Everything here is live. Nothing needs a restart, which is the point: an
// admin flipping "be a public relay" on a phone or a pod should not have to
// redeploy it, and the settings that used to require a restart were exactly the
// ones nobody could change remotely.
func recomputeSelfNodeConfig() {
	self := selfPubB64()
	if self == "" {
		return // key not loaded yet; loadNodeConfigs runs again after it is
	}
	c := effectiveNodeConfig(self)
	if c.Epoch != 0 && c.Epoch <= appliedCfgEpoch {
		return
	}
	appliedCfgEpoch = c.Epoch
	applyNodeConfigLive(c, "admin")
}

// applyNodeConfigLive is the single place that turns a record into running
// state. Shared by the gossip path and the local control API so the two cannot
// drift apart.
func applyNodeConfigLive(c SignedNodeConfig, source string) {
	var changed []string

	if c.DHT != nil {
		setDHTEnabled(*c.DHT)
		changed = append(changed, fmt.Sprintf("dht=%v", *c.DHT))
	}
	if c.UseRelays != nil && gRelayClient != nil {
		gRelayClient.SetEnabled(*c.UseRelays)
		changed = append(changed, fmt.Sprintf("use_public_relays=%v", *c.UseRelays))
	}
	if c.Trackers != nil && len(*c.Trackers) > 0 {
		// saveTrackers refuses an empty list on purpose -- a node with no
		// trackers has no way to discover peers -- so an empty one is skipped
		// here rather than passed down to be rejected.
		if err := saveTrackers(*c.Trackers); err != nil {
			log.Printf("[nodecfg] could not save tracker list: %v", err)
		} else {
			changed = append(changed, fmt.Sprintf("trackers=%d", len(*c.Trackers)))
		}
	}
	if c.TrackersOn != nil {
		setTrackersEnabled(*c.TrackersOn)
		changed = append(changed, fmt.Sprintf("trackers_on=%v", *c.TrackersOn))
	}
	if c.Rendezvous != nil {
		auth := ""
		if c.RendezvousAuth != nil {
			auth = *c.RendezvousAuth
		}
		list := []string{}
		if strings.TrimSpace(*c.Rendezvous) != "" {
			list = []string{strings.TrimSpace(*c.Rendezvous)}
		}
		if err := saveNodeRendezvous(list, auth); err != nil {
			log.Printf("[nodecfg] could not save rendezvous settings: %v", err)
		} else {
			changed = append(changed, "rendezvous="+*c.Rendezvous)
		}
	}

	// Relay bandwidth BEFORE enabling the relay, never after. Enabling first
	// leaves a window -- short, but real, and it is the window strangers are
	// actively probing for -- in which this node relays at the previous limit,
	// or at no limit at all on a first configuration.
	if gBandwidth != nil && (c.RelayUp != nil || c.RelayDown != nil || c.RelayQuota != nil) {
		// Read the current values and overwrite only the fields the record
		// actually carries: Configure takes all four at once, so passing zero
		// for an absent field would silently reset it to "unlimited".
		cur := gBandwidth.Status()
		up, down, quota := cur.UpLimitBps, cur.DownLimitBps, cur.QuotaBytes
		if c.RelayUp != nil {
			up = *c.RelayUp
			changed = append(changed, "relay_up="+formatRate(up))
		}
		if c.RelayDown != nil {
			down = *c.RelayDown
			changed = append(changed, "relay_down="+formatRate(down))
		}
		if c.RelayQuota != nil {
			quota = *c.RelayQuota
			changed = append(changed, "relay_quota="+formatRate(quota))
		}
		// An admin typed a number: stop managing it automatically.
		relayAutoShare.Store(false)
		gBandwidth.Configure(up, down, quota, cur.PeriodDays)
	}
	if c.PublicRelay != nil && gPublicRelay != nil {
		// No limit required. An unset budget means AUTOMATIC, not unlimited:
		// the governor in relayshare.go holds the relay to 80% of this node's
		// estimated capacity, leaving a fifth of the link for the node itself.
		// Refusing to start without a hand-typed number made the safe choice
		// the one that takes work, which mostly produced either no relay at
		// all or an arbitrary figure typed to get past the dialog.
		if !relayHasAnyLimit() {
			relayAutoShare.Store(true)
			if gBandwidth != nil {
				b := relayAutoBudgetBps()
				cur := gBandwidth.Status()
				gBandwidth.Configure(b, b, cur.QuotaBytes, cur.PeriodDays)
				changed = append(changed, "relay_budget=auto("+formatRate(b)+")")
			}
		}
		gPublicRelay.SetEnabled(*c.PublicRelay)
		changed = append(changed, fmt.Sprintf("public_relay=%v", *c.PublicRelay))
	}

	// Exit bandwidth, same ordering rule as the relay.
	if c.ExitUp != nil || c.ExitDown != nil || c.ExitQuota != nil {
		l := ensureExitLimiter()
		cur := l.Status()
		up, down, quota := cur.UpLimitBps, cur.DownLimitBps, cur.QuotaBytes
		if c.ExitUp != nil {
			up = *c.ExitUp
			changed = append(changed, "exit_up="+formatRate(up))
		}
		if c.ExitDown != nil {
			down = *c.ExitDown
			changed = append(changed, "exit_down="+formatRate(down))
		}
		if c.ExitQuota != nil {
			quota = *c.ExitQuota
			changed = append(changed, "exit_quota="+formatRate(quota))
		}
		l.Configure(up, down, quota, cur.PeriodDays)
	}
	if c.ExitNode != nil {
		if err := setExitNodeEnabled(*c.ExitNode); err != nil {
			log.Printf("[nodecfg] could not %s exit-node mode: %v",
				map[bool]string{true: "enable", false: "disable"}[*c.ExitNode], err)
		} else {
			changed = append(changed, fmt.Sprintf("exit_node=%v", *c.ExitNode))
		}
	}

	if len(changed) > 0 {
		log.Printf("[nodecfg] applied (%s, epoch %d): %s", source, c.Epoch, strings.Join(changed, " "))
	}
}

// relayHasAnyLimit reports whether at least one relay budget is set.
func relayHasAnyLimit() bool {
	if gBandwidth == nil {
		return false
	}
	s := gBandwidth.Status()
	return s.UpLimitBps > 0 || s.DownLimitBps > 0 || s.QuotaBytes > 0
}
