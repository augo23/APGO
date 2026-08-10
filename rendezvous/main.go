// Command rendezvous is a tiny discovery server for APGO overlays on networks
// that block BitTorrent. A node POSTs its network id (info-hash) and public
// endpoint; the server records it and returns the other current endpoints in
// that network. It is a drop-in alternative to a BitTorrent tracker, but speaks
// plain HTTP(S) — run it behind TLS on 443 (or with the built-in TLS options)
// and it looks like any other HTTPS service, so BitTorrent filters ignore it.
//
// It only exchanges endpoints (like a tracker). It never sees keys or the PSK,
// so it cannot join or decrypt the overlay; membership stays gated by the Noise
// handshake + PSK on the nodes.
//
// Env:
//
//	LISTEN_ADDR   bind address (default ":8080")
//	TLS_CERT_FILE / TLS_KEY_FILE  serve HTTPS directly (optional)
//	PEER_TTL_SECONDS  how long an endpoint stays advertised (default 300)
package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

type peerEntry struct {
	endpoint string
	lastSeen time.Time
}

type registry struct {
	mu       sync.Mutex
	nets     map[string]map[string]peerEntry // network -> endpoint -> entry
	ttl      time.Duration
	maxPeers int
}

func newRegistry(ttl time.Duration) *registry {
	return &registry{nets: map[string]map[string]peerEntry{}, ttl: ttl, maxPeers: 200}
}

// announce records endpoint (if non-empty) under network and returns the other
// live endpoints in that network.
func (r *registry) announce(network, endpoint string) []string {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	m := r.nets[network]
	if m == nil {
		m = map[string]peerEntry{}
		r.nets[network] = m
	}
	// Expire stale entries.
	for ep, e := range m {
		if now.Sub(e.lastSeen) > r.ttl {
			delete(m, ep)
		}
	}
	if endpoint != "" && len(m) < r.maxPeers {
		m[endpoint] = peerEntry{endpoint: endpoint, lastSeen: now}
	}
	out := make([]string, 0, len(m))
	for ep := range m {
		if ep != endpoint {
			out = append(out, ep)
		}
	}
	// Never leave an empty network behind: every distinct network name costs a
	// map entry that used to live FOREVER — anyone spraying random names could
	// grow this server's memory without bound.
	if len(m) == 0 {
		delete(r.nets, network)
	}
	return out
}

// sweep drops expired endpoints and empty networks. announce() already prunes
// the network being touched; this catches networks nobody announces to anymore
// (the leak: one POST with a unique name used to leave state behind for the
// life of the process).
func (r *registry) sweep() {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, m := range r.nets {
		for ep, e := range m {
			if now.Sub(e.lastSeen) > r.ttl {
				delete(m, ep)
			}
		}
		if len(m) == 0 {
			delete(r.nets, name)
		}
	}
}

// validEndpoint accepts only a plausible "host:port" (or "[v6]:port") string —
// junk never enters the registry, and clients never receive garbage to dial.
func validEndpoint(ep string) bool {
	if len(ep) == 0 || len(ep) > 64 {
		return false
	}
	host, portStr, err := net.SplitHostPort(ep)
	if err != nil || net.ParseIP(host) == nil {
		return false
	}
	p, err := strconv.Atoi(portStr)
	return err == nil && p > 0 && p <= 65535
}

func main() {
	ttl := 300
	if v, err := strconv.Atoi(os.Getenv("PEER_TTL_SECONDS")); err == nil && v > 0 {
		ttl = v
	}
	reg := newRegistry(time.Duration(ttl) * time.Second)
	// Background sweep so abandoned networks are reclaimed even when nothing
	// announces to them again.
	go func() {
		t := time.NewTicker(reg.ttl)
		defer t.Stop()
		for range t.C {
			reg.sweep()
		}
	}()

	auth := loadAuthConfig()
	auth.logStartupState()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/rendezvous", auth.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Network  string `json:"network"`
			Endpoint string `json:"endpoint"`
			PeerID   string `json:"peer_id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Network == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// The network id is a hex info-hash (40 chars); anything much longer is
		// junk. Malformed endpoints are recorded as "" (query-only announce).
		if len(req.Network) > 64 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if !validEndpoint(req.Endpoint) {
			req.Endpoint = ""
		}
		peers := reg.announce(req.Network, req.Endpoint)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"peers": peers})
	}))
	// Health check stays UNAUTHENTICATED: Kubernetes probes and load balancers
	// have no credential, and it reveals nothing (no network names, no peers).
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	// Lets a client verify its credential without announcing anything — the
	// "Test connection" button in the apps posts here.
	mux.HandleFunc("/api/auth-check", auth.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "auth_required": auth.enabled()})
	}))

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	cert, key := os.Getenv("TLS_CERT_FILE"), os.Getenv("TLS_KEY_FILE")
	if cert != "" && key != "" {
		log.Printf("APGO rendezvous listening on %s (HTTPS)", addr)
		log.Fatal(srv.ListenAndServeTLS(cert, key))
	}
	log.Printf("APGO rendezvous listening on %s (HTTP — put TLS in front for 443)", addr)
	log.Fatal(srv.ListenAndServe())
}
