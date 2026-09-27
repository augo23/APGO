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
//	RATE_PER_SECOND / RATE_BURST  per-client-IP request limit (default 2/s, burst 30)
//	TRUST_PROXY_HEADERS  "1" always trust CF-Connecting-IP / X-Real-IP /
//	              X-Forwarded-For, "0" never; default: only when the direct
//	              peer is a local (loopback/private) reverse proxy
//
// An announced endpoint is only recorded if its host is the requesting
// client's own IP (or, across address families, capped per client) — so the
// server can't be used to point a network at someone else's address.
package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type peerEntry struct {
	endpoint string
	source   string // client IP the announce came from (see sourceIP)
	verified bool   // endpoint host == source IP
	lastSeen time.Time
}

type registry struct {
	mu       sync.Mutex
	nets     map[string]map[string]peerEntry // network -> endpoint -> entry
	ttl      time.Duration
	maxPeers int
	// Per-source caps. An endpoint whose host is the requester's own IP is
	// "verified" (at worst a NAT'd site advertising its own address, so the
	// cap is generous); one in the other address family can't be checked and
	// gets a tight cap so a single client can't fill a network with addresses
	// of its choosing.
	maxPerSourceVerified   int
	maxPerSourceUnverified int
	maxNetworks            int
}

func newRegistry(ttl time.Duration) *registry {
	return &registry{
		nets:                   map[string]map[string]peerEntry{},
		ttl:                    ttl,
		maxPeers:               200,
		maxPerSourceVerified:   64,
		maxPerSourceUnverified: 4,
		maxNetworks:            50000,
	}
}

// announce records endpoint (if non-empty) under network on behalf of source
// and returns the other live endpoints in that network.
func (r *registry) announce(network, endpoint, source string, verified bool) []string {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	m := r.nets[network]
	if m == nil {
		if endpoint == "" || len(r.nets) >= r.maxNetworks {
			return []string{} // query-only for an unknown network, or full
		}
		m = map[string]peerEntry{}
		r.nets[network] = m
	}
	// Expire stale entries, counting this source's live ones as we go.
	fromSource := 0
	for ep, e := range m {
		if now.Sub(e.lastSeen) > r.ttl {
			delete(m, ep)
			continue
		}
		if e.source == source && e.verified == verified && ep != endpoint {
			fromSource++
		}
	}
	if endpoint != "" {
		limit := r.maxPerSourceUnverified
		if verified {
			limit = r.maxPerSourceVerified
		}
		_, refresh := m[endpoint]
		if refresh || (len(m) < r.maxPeers && fromSource < limit) {
			m[endpoint] = peerEntry{endpoint: endpoint, source: source, verified: verified, lastSeen: now}
		}
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

// checkEndpoint decides whether an announced endpoint may be recorded for a
// request from source. The endpoint is chosen by the CLIENT (its STUN-mapped
// UDP address), so without this check anyone could register a victim's
// address and have every node in the network send handshakes to it, or pack
// a network with fake addresses. Rules:
//
//   - same address family as the request: the host MUST be the requester's
//     own IP (the port is the client's to choose — its NAT mapping);
//   - different family (a dual-stack node reaching us over IPv6 while
//     announcing its IPv4 mapping, or vice versa): can't be checked, so it
//     is accepted as "unverified" and capped per source (registry);
//   - a request from a private address (a node on the server's own LAN,
//     no proxy header) is likewise unverifiable: accepted, capped;
//   - non-public endpoint hosts (loopback, private, link-local, multicast,
//     unspecified) are never recorded.
func checkEndpoint(ep, source string) (ok, verified bool) {
	host, _, err := net.SplitHostPort(ep)
	if err != nil {
		return false, false
	}
	hip, sip := net.ParseIP(host), net.ParseIP(source)
	if hip == nil || !isPublicIP(hip) {
		return false, false
	}
	if sip == nil {
		return false, false
	}
	if !isPublicIP(sip) {
		// The request came from a private address with no proxy header (a
		// node on the server's own LAN): its public mapping can't be checked,
		// so treat it like a cross-family announce — accepted, capped.
		return true, false
	}
	if (hip.To4() != nil) == (sip.To4() != nil) {
		return hip.Equal(sip), true
	}
	return true, false
}

func isPublicIP(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		ip.IsInterfaceLocalMulticast() || cgnat.Contains(ip))
}

var cgnat = func() *net.IPNet { _, n, _ := net.ParseCIDR("100.64.0.0/10"); return n }()

// sourceIP returns the requesting client's IP. When the direct peer is a
// local reverse proxy (loopback or private address — Caddy, nginx, a
// Cloudflare Tunnel's cloudflared), the client IP is taken from the proxy's
// header instead: CF-Connecting-IP, X-Real-IP, then the LAST hop of
// X-Forwarded-For (the one the proxy itself appended). TRUST_PROXY_HEADERS=0
// disables this; =1 trusts the headers from any peer (only safe when the
// server is reachable solely through the proxy).
func sourceIP(r *http.Request, trust string) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	direct := net.ParseIP(host)
	useHeaders := false
	switch trust {
	case "0", "false", "no", "off":
	case "1", "true", "yes", "on":
		useHeaders = true
	default:
		useHeaders = direct != nil && (direct.IsLoopback() || direct.IsPrivate())
	}
	if useHeaders {
		for _, h := range []string{"CF-Connecting-IP", "X-Real-IP"} {
			if ip := net.ParseIP(strings.TrimSpace(r.Header.Get(h))); ip != nil {
				return ip.String()
			}
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
				return ip.String()
			}
		}
	}
	if direct != nil {
		return direct.String()
	}
	return host
}

// rateLimiter is a per-source token bucket. Nodes announce about once a
// minute, so the defaults leave room for a large site behind one NAT while
// stopping a single host from hammering the registry.
type rateLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate, burst float64) *rateLimiter {
	return &rateLimiter{rate: rate, burst: burst, buckets: map[string]*bucket{}}
}

func (l *rateLimiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) > 100000 {
			for k, v := range l.buckets {
				if now.Sub(v.last) > time.Minute {
					delete(l.buckets, k)
				}
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func envFloat(name string, def float64) float64 {
	if v, err := strconv.ParseFloat(os.Getenv(name), 64); err == nil && v > 0 {
		return v
	}
	return def
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
	trustProxy := strings.ToLower(strings.TrimSpace(os.Getenv("TRUST_PROXY_HEADERS")))
	limiter := newRateLimiter(envFloat("RATE_PER_SECOND", 2), envFloat("RATE_BURST", 30))

	mux := http.NewServeMux()
	mux.HandleFunc("/api/rendezvous", auth.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		src := sourceIP(r, trustProxy)
		if !limiter.allow(src) {
			http.Error(w, "slow down", http.StatusTooManyRequests)
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
		verified := false
		if !validEndpoint(req.Endpoint) {
			req.Endpoint = ""
		} else if ok, v := checkEndpoint(req.Endpoint, src); !ok {
			// Someone else's address (or a non-public one): answer the query,
			// record nothing.
			req.Endpoint = ""
		} else {
			verified = v
		}
		peers := reg.announce(req.Network, req.Endpoint, src, verified)
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
