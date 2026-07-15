package main

// setup.go lets an UNCONFIGURED node be set up from the web (parity with the
// macOS app's settings window). If the client starts with no network_name/PSK
// (no config file, no env/secret), instead of failing it serves a tiny setup API
// on the control socket and waits. The admin dashboard posts the network details
// to it; they're persisted to SETUP_FILE (on the state volume) and the client
// restarts into its configured state. Works the same for Compose and Kubernetes.

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func setupFilePath() string {
	if p := os.Getenv("SETUP_FILE"); p != "" {
		return p
	}
	return "/state/setup.json"
}


type setupData struct {
	NetworkName  string `json:"network_name"`
	PSK          string `json:"psk"`
	OverlayCIDR  string `json:"overlay_cidr"`
	Address      string `json:"address"` // optional static overlay IP/CIDR
	FriendlyName string `json:"friendly_name"`
	PostQuantum  bool   `json:"post_quantum"`
}

// applySetupFile fills any blanks in cfg from a persisted web-setup file.
func applySetupFile(cfg *ClientConfig) {
	data, err := os.ReadFile(setupFilePath())
	if err != nil {
		return
	}
	var s setupData
	if json.Unmarshal(data, &s) != nil {
		return
	}
	if cfg.NetworkName == "" {
		cfg.NetworkName = s.NetworkName
	}
	if cfg.PSK == "" {
		cfg.PSK = s.PSK
	}
	if cfg.OverlayCIDR == "" && s.OverlayCIDR != "" {
		cfg.OverlayCIDR = s.OverlayCIDR
	}
	if cfg.FriendlyName == "" {
		cfg.FriendlyName = s.FriendlyName
	}
	if cfg.Tun.AddressCIDR == "" && s.Address != "" {
		cfg.Tun.AddressCIDR = s.Address
	}
	if s.PostQuantum {
		cfg.PostQuantum = true
	}
}

func needsSetup(cfg *ClientConfig) bool {
	return strings.TrimSpace(cfg.NetworkName) == "" || strings.TrimSpace(cfg.PSK) == ""
}

// runSetupServerAndWait serves the setup API on the control socket and blocks.
// On a successful POST it persists the config and exits(0) so the supervisor
// (Compose restart policy / Kubernetes) restarts the client, now configured.
func runSetupServerAndWait(sock string) {
	if sock == "" {
		log.Fatalf("no network config (network_name + psk) and no CONTROL_SOCKET for web setup — set them in config/env or via the admin dashboard")
	}
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		log.Fatalf("[setup] cannot listen on %s: %v", sock, err)
	}
	_ = os.Chmod(sock, 0o666)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"needs_setup": true})
	})
	mux.HandleFunc("/api/setup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var s setupData
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&s) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		s.NetworkName = strings.TrimSpace(s.NetworkName)
		s.PSK = strings.TrimSpace(s.PSK)
		if s.NetworkName == "" {
			http.Error(w, "network name is required", http.StatusBadRequest)
			return
		}
		// Generate a PSK if blank; otherwise require the base64: prefix.
		if s.PSK == "" {
			s.PSK = generatePSK()
		} else if !strings.HasPrefix(s.PSK, "base64:") {
			http.Error(w, "PSK must start with base64: (or leave blank to generate one)", http.StatusBadRequest)
			return
		}
		if s.OverlayCIDR == "" {
			s.OverlayCIDR = "10.28.55.0/24"
		}
		blob, _ := json.MarshalIndent(s, "", "  ")
		tmp := setupFilePath() + ".tmp"
		if os.WriteFile(tmp, blob, 0o600) != nil || os.Rename(tmp, setupFilePath()) != nil {
			http.Error(w, "could not save setup (is the state volume writable?)", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "psk": s.PSK})
		log.Printf("[setup] network configured via dashboard — restarting to apply")
		go func() { time.Sleep(500 * time.Millisecond); _ = ln.Close(); os.Exit(0) }()
	})

	srv := &http.Server{Handler: mux}
	log.Printf("[setup] node not configured — open the admin dashboard to set the network name + PSK (waiting)…")
	_ = srv.Serve(ln)
}
