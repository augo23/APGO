//go:build darwin || windows

package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// fakeClient serves the control socket. exits is the /api/exits reply;
// status is the reply code for everything else.
type fakeClient struct {
	mu    sync.Mutex
	calls []string
	exits string
}

func (f *fakeClient) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func startFakeClient(t *testing.T, status int, exits string) *fakeClient {
	t.Helper()
	_ = os.Remove(controlSocket())
	ln, err := net.Listen("unix", controlSocket())
	if err != nil {
		t.Fatal(err)
	}
	fc := &fakeClient{exits: exits}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/exits" {
			_, _ = w.Write([]byte(fc.exits))
			return
		}
		if r.URL.Path == "/api/info" {
			_, _ = w.Write([]byte(`{"exit_node":false}`))
			return
		}
		b, _ := io.ReadAll(r.Body)
		fc.mu.Lock()
		fc.calls = append(fc.calls, r.URL.Path+" "+string(b))
		fc.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); _ = os.Remove(controlSocket()) })
	return fc
}

func TestFullVPNAppliesLiveAndPersists(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	c := blankConfig()
	c.NetworkName, c.PSK = "home", "x"
	if err := saveConfig(c); err != nil {
		t.Fatal(err)
	}
	fc := startFakeClient(t, http.StatusOK, `{"use_exit":false,"pin":""}`)

	if msg := applyFullVPNLive(true, "10.22.22.22"); !strings.Contains(msg, "10.22.22.22") {
		t.Fatalf("message: %q", msg)
	}
	got := fc.got()
	if len(got) != 1 || !strings.HasPrefix(got[0], "/api/use-exit ") {
		t.Fatalf("client not called: %v", got)
	}
	var body map[string]any
	_ = json.Unmarshal([]byte(strings.TrimPrefix(got[0], "/api/use-exit ")), &body)
	if body["use_exit"] != true || body["exit_peer"] != "10.22.22.22" {
		t.Fatalf("body %v", body)
	}

	// Compared with what the RUNNING client does, not with the old file: a
	// setting saved while the client ignored it is still pushed.
	if !fullVPNDiffers(true, "10.22.22.22", true, "10.22.22.22") {
		t.Fatal("running client is off but the saved choice is on: must apply")
	}
	fc.mu.Lock()
	fc.exits = `{"use_exit":true,"pin":"10.22.22.22"}`
	fc.mu.Unlock()
	if fullVPNDiffers(true, "10.22.22.22", false, "") {
		t.Fatal("running client already matches: nothing to apply")
	}

	// Dashboard network row for the MAIN network: persisted and forwarded.
	req := httptest.NewRequest("POST", "/api/network-set", strings.NewReader(`{"network_name":"home","use_exit":true}`))
	rec := httptest.NewRecorder()
	handlePanelNetworkSet(rec, req)
	got = fc.got()
	if rec.Code != http.StatusOK || len(got) != 2 || !strings.HasPrefix(got[1], "/api/network-set ") {
		t.Fatalf("not forwarded: %d %v", rec.Code, got)
	}
	if !loadConfig().UseExit {
		t.Fatal("use_exit not saved to the config file")
	}
	// Another network's row does not touch the main config.
	req = httptest.NewRequest("POST", "/api/network-set", strings.NewReader(`{"network_name":"guest","use_exit":false}`))
	handlePanelNetworkSet(httptest.NewRecorder(), req)
	if !loadConfig().UseExit {
		t.Fatal("another network's request changed the main config")
	}
}

func TestFullVPNOldOrStoppedClient(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	startFakeClient(t, http.StatusNotFound, `{}`)
	if msg := applyFullVPNLive(true, ""); !strings.Contains(msg, "Disconnect and Connect") {
		t.Fatalf("message: %q", msg)
	}
	_ = os.Remove(controlSocket())
	if msg := applyFullVPNLive(true, ""); msg != "" {
		t.Fatalf("a stopped client should need no message, got %q", msg)
	}
}

func TestExitNodeAppliesLive(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	fc := startFakeClient(t, http.StatusOK, `{}`)
	if !exitNodeDiffers(true, true) {
		t.Fatal("running client is not an exit but the saved choice is: must apply")
	}
	if exitNodeDiffers(false, true) {
		t.Fatal("running client already matches")
	}
	if msg := applyExitNodeLive(true); !strings.Contains(msg, "now an internal exit node") {
		t.Fatalf("message: %q", msg)
	}
	got := fc.got()
	if len(got) != 1 || got[0] != `/api/exit-node {"exit_node":true}` {
		t.Fatalf("client call: %v", got)
	}
}

func TestExitNodeFailureIsReported(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	startFakeClient(t, http.StatusInternalServerError, `{}`)
	if msg := applyExitNodeLive(true); !strings.Contains(msg, "could not become an internal exit node") {
		t.Fatalf("message: %q", msg)
	}
}
