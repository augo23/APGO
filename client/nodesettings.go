package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// nodesettings.go persists per-node local toggles that an admin panel can flip
// at runtime (currently just the IPv6 transport). These are LOCAL to the node
// (not gossiped, not admin-signed) and take effect on the next restart, because
// changing them re-binds the UDP socket. The file path comes from the
// NODE_SETTINGS_FILE env (the compose stack points it at /state so it persists).

type nodeSettings struct {
	// IPv6 is a pointer so "unset" (nil) means "fall back to config/env".
	IPv6 *bool `json:"ipv6,omitempty"`
	// ExitPeer is the pinned outproxy ("" = automatic/fastest). Pointer so
	// "unset" (nil) means "fall back to config/env". Unlike IPv6 it also
	// applies LIVE (via setExitPin) — no restart needed.
	ExitPeer *string `json:"exit_peer,omitempty"`
	// Rendezvous discovery, settable from the admin panel so a containerized
	// node (where there is no desktop Settings window) can be pointed at a
	// discovery server without editing YAML and redeploying. Pointers so
	// "unset" falls back to config/env. RendezvousAuth is the combined
	// credential: "user:pass" = HTTP Basic, bare = Bearer, "" = none.
	RendezvousServers *[]string `json:"rendezvous_servers,omitempty"`
	RendezvousAuth    *string   `json:"rendezvous_auth,omitempty"`

	// DHT / public-relay toggles, settable from the admin panel so a
	// CONTAINER node — which has no desktop Settings window — can be turned
	// into a public relay, or have its bandwidth donation adjusted, without
	// editing YAML and redeploying. Pointers so "unset" falls back to
	// config/env. All apply live except DHT, which takes effect immediately
	// too (the routing table is kept, so re-enabling is instant).
	DHT         *bool `json:"dht,omitempty"`
	UseRelays   *bool `json:"use_public_relays,omitempty"`
	PublicRelay *bool `json:"public_relay,omitempty"`
	// Limits are stored as BYTES PER SECOND (and bytes, for the quota) —
	// already parsed, so the panel round-trips exact numbers rather than
	// re-parsing a human string on every read.
	RelayUpLimit   *int64 `json:"relay_up_limit,omitempty"`
	RelayDownLimit *int64 `json:"relay_down_limit,omitempty"`
	RelayQuota     *int64 `json:"relay_quota,omitempty"`
}

// saveNodeRelaySettings persists the DHT + public-relay choices made in the
// admin panel and applies them to the running node.
func saveNodeRelaySettings(dht, useRelays, publicRelay bool, upBps, downBps, quotaBytes int64) error {
	p := nodeSettingsPath()
	if p == "" {
		return os.ErrInvalid
	}
	nodeSettingsMu.Lock()
	s := nodeSettings{}
	if data, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(data, &s)
	}
	s.DHT = &dht
	s.UseRelays = &useRelays
	s.PublicRelay = &publicRelay
	s.RelayUpLimit = &upBps
	s.RelayDownLimit = &downBps
	s.RelayQuota = &quotaBytes
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		nodeSettingsMu.Unlock()
		return err
	}
	tmp := p + ".tmp"
	if err := writeFileNoFollow(tmp, out, 0o600); err != nil {
		nodeSettingsMu.Unlock()
		return err
	}
	err = os.Rename(tmp, p)
	nodeSettingsMu.Unlock()
	if err != nil {
		return err
	}
	// Apply live. Persisting without applying is the failure mode that makes
	// a panel feel broken: the operator flips a switch, nothing changes, and
	// only a restart reveals that the setting did save.
	setDHTEnabled(dht)
	if gRelayClient != nil {
		gRelayClient.SetEnabled(useRelays)
	}
	if gBandwidth != nil {
		gBandwidth.Configure(upBps, downBps, quotaBytes, 0)
	}
	if gPublicRelay != nil {
		gPublicRelay.SetEnabled(publicRelay)
	}
	return nil
}

// saveNodeRendezvous persists the rendezvous server list + credential.
func saveNodeRendezvous(servers []string, auth string) error {
	p := nodeSettingsPath()
	if p == "" {
		return os.ErrInvalid
	}
	nodeSettingsMu.Lock()
	defer nodeSettingsMu.Unlock()
	s := nodeSettings{}
	if data, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(data, &s)
	}
	s.RendezvousServers = &servers
	s.RendezvousAuth = &auth
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := writeFileNoFollow(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

var nodeSettingsMu sync.Mutex

// nodeSettingsPath is where the per-node overrides live. NODE_SETTINGS_FILE
// when set; otherwise node-settings.json beside the signed node-config file
// (NODE_CONFIG_FILE, default /state/nodeconfig.json), when that directory
// exists.
//
// The fallback matters. Without it, a node started without NODE_SETTINGS_FILE
// (a hand-run podman container, say) accepted an admin's IPv6 or rendezvous
// change, verified it, and then failed to store it with "invalid argument" --
// so the dashboard said the change was sent and nothing ever happened.
func nodeSettingsPath() string {
	if p := os.Getenv("NODE_SETTINGS_FILE"); p != "" {
		return p
	}
	dir := filepath.Dir(nodeConfigFilePath())
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		return filepath.Join(dir, "node-settings.json")
	}
	return ""
}

// loadNodeSettings reads the persisted overrides, if any.
func loadNodeSettings() nodeSettings {
	var s nodeSettings
	p := nodeSettingsPath()
	if p == "" {
		return s
	}
	nodeSettingsMu.Lock()
	defer nodeSettingsMu.Unlock()
	if data, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(data, &s)
	}
	return s
}

// saveNodeIPv6 persists the IPv6 override. Returns an error if no settings path
// is configured or the write fails.
func saveNodeIPv6(enabled bool) error {
	p := nodeSettingsPath()
	if p == "" {
		return os.ErrInvalid
	}
	nodeSettingsMu.Lock()
	defer nodeSettingsMu.Unlock()
	s := nodeSettings{}
	if data, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(data, &s)
	}
	s.IPv6 = &enabled
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileNoFollow(p, out, 0o644)
}

// saveNodeExitPin persists the pinned-outproxy override ("" = automatic).
// Returns an error if no settings path is configured or the write fails.
func saveNodeExitPin(pin string) error {
	p := nodeSettingsPath()
	if p == "" {
		return os.ErrInvalid
	}
	nodeSettingsMu.Lock()
	defer nodeSettingsMu.Unlock()
	s := nodeSettings{}
	if data, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(data, &s)
	}
	s.ExitPeer = &pin
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileNoFollow(p, out, 0o644)
}

// applyNodeSettings overrides the live toggles from the persisted file. Called
// after config + env so a panel-set choice is authoritative across restarts.
func applyNodeSettings() {
	s := loadNodeSettings()
	if s.IPv6 != nil {
		ipv6Enabled = *s.IPv6
	}
}
