package main

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Full VPN moved from the Settings form to the dashboard's main page. Saving
// the form must therefore leave the saved Full VPN choice alone; before, the
// form's (now absent) use_exit box would have read as "off" and silently
// turned Full VPN off on every Save.
func TestSettingsSaveKeepsFullVPNChoice(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	c := blankConfig()
	c.NetworkName = "home"
	c.PSK = "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	c.UseExit, c.ExitPeer, c.UsePublicExits = true, "9af9a5e5cf4a", true
	if err := saveConfig(c); err != nil {
		t.Fatal(err)
	}

	form := url.Values{"network_name": {"home"}, "psk": {c.PSK}, "friendly_name": {"mac"}, "dht": {"on"}}
	r := httptest.NewRequest("POST", "/settings", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := saveSettingsForm(r); err != nil {
		t.Fatal(err)
	}
	got := loadConfig()
	if !got.UseExit || got.ExitPeer != "9af9a5e5cf4a" || !got.UsePublicExits {
		t.Fatalf("Settings save changed Full VPN: use_exit=%v exit_peer=%q use_public=%v",
			got.UseExit, got.ExitPeer, got.UsePublicExits)
	}
	if got.FriendlyName != "mac" {
		t.Fatalf("form field not saved: %q", got.FriendlyName)
	}

	// Switching to a different network drops the old network's exit choice.
	form.Set("network_name", "work")
	r = httptest.NewRequest("POST", "/settings", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := saveSettingsForm(r); err != nil {
		t.Fatal(err)
	}
	if got := loadConfig(); got.UseExit || got.ExitPeer != "" {
		t.Fatalf("new network inherited Full VPN: use_exit=%v exit_peer=%q", got.UseExit, got.ExitPeer)
	}
}

func TestSettingsPageHasTabsAndNoFullVPN(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	page := settingsPage(blankConfig())
	for _, id := range []string{"tab-device", "tab-network", "tab-discovery", "tab-sharing", "tab-admin",
		"pane-device", "pane-network", "pane-discovery", "pane-sharing", "pane-admin"} {
		if !strings.Contains(page, `id="`+id+`"`) {
			t.Errorf("settings page is missing #%s", id)
		}
	}
	for _, gone := range []string{`name="use_exit"`, `name="exit_peer"`, `name="use_public_exits"`, "{{"} {
		if strings.Contains(page, gone) {
			t.Errorf("settings page still contains %s", gone)
		}
	}
}
