package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// TestAPIInfoServesCleanly exercises the EXACT call the desktop app makes to
// decide "is a client running / what are my peers". If this handler panics,
// hangs or emits invalid JSON, the client keeps running perfectly (phones
// still see it) while the app reports a connection error and an empty peer
// list — precisely the symptom being chased. No TUN required.
func TestAPIInfoServesCleanly(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	// Minimal state the handler touches, as a fresh process would have it.
	GlobalSessions = NewSessionTable(nil)
	sessions = GlobalSessions
	myUDPPort = 45123
	overlayCIDR = "10.99.0.0/24"
	_, n, _ := net.ParseCIDR(overlayCIDR)
	overlayNet = n

	go startControlServer(sock)
	time.Sleep(400 * time.Millisecond)

	cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}

	for _, path := range []string{"/api/info", "/api/sessions", "/api/exits", "/api/rendezvous-config"} {
		start := time.Now()
		resp, err := cl.Get("http://unix" + path)
		if err != nil {
			t.Fatalf("%s: request failed (this is what the app sees as a connection error): %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d body=%s", path, resp.StatusCode, body)
			continue
		}
		var m any
		if err := json.Unmarshal(body, &m); err != nil {
			t.Errorf("%s: INVALID JSON (%v) body=%s", path, err, body)
			continue
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s: took %v — the app's client timeout would treat this as 'not running'", path, d)
		}
		t.Logf("%s OK in %v (%d bytes)", path, time.Since(start).Round(time.Millisecond), len(body))
	}

	// The specific fields the app and panels read.
	resp, err := cl.Get("http://unix/api/info")
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	var info map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		t.Fatalf("/api/info decode failed — fetchInfo() would return false: %v", err)
	}
	for _, k := range []string{"overlay_ip", "sessions", "ipv6_global", "inbound_ok", "listen_port", "advertise_port"} {
		if _, ok := info[k]; !ok {
			t.Errorf("/api/info missing %q (panels read it)", k)
		}
	}
	if _, bad := info["needs_setup"]; bad {
		t.Error("/api/info on a CONFIGURED client must not report needs_setup — the app would wait for a handoff that never comes")
	}
}
