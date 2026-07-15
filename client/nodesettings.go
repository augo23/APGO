package main

import (
	"encoding/json"
	"os"
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
}

var nodeSettingsMu sync.Mutex

func nodeSettingsPath() string { return os.Getenv("NODE_SETTINGS_FILE") }

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
	return os.WriteFile(p, out, 0o644)
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
	return os.WriteFile(p, out, 0o644)
}

// applyNodeSettings overrides the live toggles from the persisted file. Called
// after config + env so a panel-set choice is authoritative across restarts.
func applyNodeSettings() {
	s := loadNodeSettings()
	if s.IPv6 != nil {
		ipv6Enabled = *s.IPv6
	}
}
