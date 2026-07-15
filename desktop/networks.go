package main

// networks.go — multi-network profiles for the tray app (macOS + Windows).
//
// Each saved network is a full snapshot of client.yaml stored in
// ~/.apgo/networks/<name>.yaml. client.yaml stays the ACTIVE config (what the
// client actually runs off), so the client itself needs no changes: switching
// snapshots the current config into its own profile, copies the chosen profile
// over client.yaml, and reconnects if the client was running.
//
// Profiles are created two ways:
//   * automatically — every Settings save with a network name registers/updates
//     that network's profile (so adding a network is just: Settings → enter the
//     new name/PSK → Save), and
//   * explicitly — "Save current as network" in the tray submenu.
//
// The node key (~/.apgo/node.key) is intentionally SHARED across networks, so
// this device keeps one stable identity everywhere.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/getlantern/systray"
	"gopkg.in/yaml.v3"
)

var (
	netMu      sync.Mutex
	netItems   map[string]*systray.MenuItem // network name -> submenu item
	mNetworks  *systray.MenuItem
	mNetSave   *systray.MenuItem
	mNetDelete *systray.MenuItem
)

func networksDir() string {
	d := filepath.Join(appDir(), "networks")
	_ = os.MkdirAll(d, 0o700)
	return d
}

// profileFile maps a network name to its snapshot path (filesystem-safe).
func profileFile(name string) string {
	s := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		}
		return '_'
	}, strings.TrimSpace(name))
	return filepath.Join(networksDir(), s+".yaml")
}

// listProfiles returns the saved network names, sorted.
func listProfiles() []string {
	entries, err := os.ReadDir(networksDir())
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		var c mConfig
		if data, err := os.ReadFile(filepath.Join(networksDir(), e.Name())); err == nil {
			_ = yaml.Unmarshal(data, &c)
		}
		name := strings.TrimSpace(c.NetworkName)
		if name == "" {
			name = strings.TrimSuffix(e.Name(), ".yaml")
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// registerCurrentProfile snapshots the ACTIVE config as a named profile.
func registerCurrentProfile() (string, error) {
	c := loadConfig()
	if strings.TrimSpace(c.NetworkName) == "" {
		return "", fmt.Errorf("set a network name in Settings first")
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return "", err
	}
	return c.NetworkName, os.WriteFile(profileFile(c.NetworkName), data, 0o600)
}

// registerCurrentProfileUI registers the active config and syncs the submenu.
// Called from Settings saves too, which is what makes network adding dynamic.
func registerCurrentProfileUI() {
	name, err := registerCurrentProfile()
	if err != nil {
		return
	}
	netMu.Lock()
	ready := netItems != nil
	_, exists := netItems[name]
	netMu.Unlock()
	if ready && !exists {
		addNetworkItem(name)
	}
	refreshNetworkChecks()
}

// switchToProfile makes `name` the active network. The current config is
// snapshotted first so its latest edits are never lost, and the client is
// bounced if it was running (it only reads client.yaml at start).
func switchToProfile(name string) {
	data, err := os.ReadFile(profileFile(name))
	if err != nil {
		notify("Couldn't load network \"" + name + "\": " + err.Error())
		return
	}
	// Sanity-check the YAML before overwriting the active config.
	c := mConfig{PostQuantum: true, IPv6: true}
	if err := yaml.Unmarshal(data, &c); err != nil {
		notify("Network \"" + name + "\" has a corrupt profile: " + err.Error())
		return
	}
	if cur := loadConfig(); strings.TrimSpace(cur.NetworkName) != "" && cur.NetworkName != name {
		_, _ = registerCurrentProfile()
	}
	if err := os.WriteFile(configPath(), data, 0o600); err != nil {
		notify("Couldn't switch network: " + err.Error())
		return
	}
	if _, running := fetchInfo(); running {
		doDisconnect()
		time.Sleep(1500 * time.Millisecond)
		doConnect()
		notify("Switched to \"" + name + "\" and reconnecting.")
	} else {
		notify("Switched to \"" + name + "\". Click Connect to join.")
	}
	refreshNetworkChecks()
}

// deleteCurrentProfile removes the saved profile matching the active config's
// network name (the active client.yaml itself is left untouched).
func deleteCurrentProfile() {
	name := strings.TrimSpace(loadConfig().NetworkName)
	if name == "" {
		notify("No current network to delete.")
		return
	}
	if err := os.Remove(profileFile(name)); err != nil {
		notify("Couldn't delete \"" + name + "\": " + err.Error())
		return
	}
	netMu.Lock()
	if it := netItems[name]; it != nil {
		it.Hide()
		delete(netItems, name)
	}
	netMu.Unlock()
	notify("Deleted saved network \"" + name + "\". Current settings are unchanged.")
}

// setupNetworksMenu builds the "Networks" tray submenu. Call from onReady, in
// menu order (after Settings/Admin, before Start-at-login).
func setupNetworksMenu() {
	mNetworks = systray.AddMenuItem("Networks", "Switch between saved networks")
	netMu.Lock()
	netItems = map[string]*systray.MenuItem{}
	netMu.Unlock()
	for _, name := range listProfiles() {
		addNetworkItem(name)
	}
	mNetSave = mNetworks.AddSubMenuItem("Save current as network",
		"Snapshot the current settings as a switchable network")
	mNetDelete = mNetworks.AddSubMenuItem("Delete current network",
		"Remove the saved profile for the current network name")

	go func() {
		for {
			select {
			case <-mNetSave.ClickedCh:
				if name, err := registerCurrentProfile(); err != nil {
					notify("Couldn't save network: " + err.Error())
				} else {
					netMu.Lock()
					_, exists := netItems[name]
					netMu.Unlock()
					if !exists {
						addNetworkItem(name)
					}
					notify("Saved \"" + name + "\" — switch networks from this menu.")
					refreshNetworkChecks()
				}
			case <-mNetDelete.ClickedCh:
				deleteCurrentProfile()
			}
		}
	}()
	refreshNetworkChecks()
}

// addNetworkItem appends one switchable network to the submenu.
func addNetworkItem(name string) {
	item := mNetworks.AddSubMenuItemCheckbox(name, "Switch to this network", false)
	netMu.Lock()
	netItems[name] = item
	netMu.Unlock()
	go func() {
		for range item.ClickedCh {
			switchToProfile(name)
		}
	}()
}

// refreshNetworkChecks checkmarks the submenu entry matching the active config.
func refreshNetworkChecks() {
	netMu.Lock()
	defer netMu.Unlock()
	if netItems == nil {
		return
	}
	cur := loadConfig().NetworkName
	for n, it := range netItems {
		if n == cur {
			it.Check()
		} else {
			it.Uncheck()
		}
	}
}
