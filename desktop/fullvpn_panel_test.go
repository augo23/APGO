//go:build darwin || windows

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postFullVPN(t *testing.T, body string, xrw bool) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/full-vpn", strings.NewReader(body))
	if xrw {
		r.Header.Set("X-Requested-With", "overlay-admin")
	}
	w := httptest.NewRecorder()
	handlePanelFullVPN(w, r)
	return w
}

// The main-page panel: GET shows the saved choice and the live exit list;
// POST saves the choice and applies it to the running client.
func TestFullVPNPanelPinsAnExit(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	c := blankConfig()
	c.NetworkName, c.PSK = "home", "x"
	if err := saveConfig(c); err != nil {
		t.Fatal(err)
	}
	fc := startFakeClient(t, http.StatusOK,
		`{"use_exit":false,"pin":"","use_public_exits":false,"exits":[{"overlay_ip":"10.22.22.7","name":"zx7t","key_fp":"9af9a5e5cf4a","rtt_ms":21,"reachable":true}]}`)

	w := httptest.NewRecorder()
	handlePanelFullVPN(w, httptest.NewRequest("GET", "/api/full-vpn", nil))
	var st struct {
		UseExit   bool `json:"use_exit"`
		Connected bool `json:"connected"`
		Live      struct {
			Exits []struct {
				KeyFP string `json:"key_fp"`
			} `json:"exits"`
		} `json:"live"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.UseExit || !st.Connected || len(st.Live.Exits) != 1 || st.Live.Exits[0].KeyFP != "9af9a5e5cf4a" {
		t.Fatalf("GET: %s", w.Body.String())
	}

	if w := postFullVPN(t, `{"use_exit":true,"exit_peer":"9af9a5e5cf4a"}`, false); w.Code != http.StatusBadRequest {
		t.Fatalf("POST without X-Requested-With: %d, want 400", w.Code)
	}
	if w := postFullVPN(t, `{"use_exit":true,"exit_peer":"9af9a5e5cf4a"}`, true); w.Code != http.StatusOK {
		t.Fatalf("POST: %d %s", w.Code, w.Body.String())
	}
	got := loadConfig()
	if !got.UseExit || got.ExitPeer != "9af9a5e5cf4a" {
		t.Fatalf("not saved: use_exit=%v exit_peer=%q", got.UseExit, got.ExitPeer)
	}
	var applied bool
	for _, call := range fc.got() {
		if strings.HasPrefix(call, "/api/use-exit ") && strings.Contains(call, `"exit_peer":"9af9a5e5cf4a"`) &&
			strings.Contains(call, `"use_exit":true`) {
			applied = true
		}
	}
	if !applied {
		t.Fatalf("not applied to the client: %v", fc.got())
	}

	if w := postFullVPN(t, `{"exit_peer":"bad\nvalue"}`, true); w.Code != http.StatusBadRequest {
		t.Fatalf("multi-line exit_peer accepted: %d", w.Code)
	}
}
