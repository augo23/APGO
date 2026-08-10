package main

// multinet.go — concurrent secondary networks ("guest networks").
//
// A node can belong to several overlay networks at once. Each ADDITIONAL
// network runs as a CHILD PROCESS of this client (same binary, re-exec'd),
// with its own generated config, TUN interface, UDP port, control socket and
// state directory — the architecture already proven by two clients sharing a
// host (docs/two-nodes-same-host.md), now supervised from inside the client.
// Process-per-network keeps every existing single-network invariant intact:
// no global state is shared between networks, a crash in one network cannot
// take down another, and membership isolation stays cryptographic (a node
// that doesn't run a network's profile can't be handshaken by its members).
//
// The node KEY is shared across networks (one stable device identity); the
// derived overlay IP still differs per network because each network has its
// own overlay_cidr.
//
// Secondary networks come from three places, merged in this order (first
// definition of a network_name wins):
//   1. the config file's `networks:` list,
//   2. networks added at runtime via the control API (/api/network-add),
//   3. networks a signed share record instructed this node to join
//      (netshare.go) — both 2 and 3 persist under <state>/networks/<id>/.
//
// Exactly ONE network (main or secondary) may have use_exit: the full-VPN
// default route can only point one way. The supervisor enforces this,
// keeping the first claimant and disabling the rest with a loud log.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// SecondaryNetwork is one additional overlay network this node participates
// in. Zero values inherit the main network's setting where that makes sense
// (cipher, PQ, MTU, IPv6, STUN, trackers).
type SecondaryNetwork struct {
	NetworkName string `yaml:"network_name" json:"network_name"`
	PSK         string `yaml:"psk" json:"psk,omitempty"`
	OverlayCIDR string `yaml:"overlay_cidr" json:"overlay_cidr"`
	// TunName defaults to "apg" + first 4 hex chars of the network id.
	TunName       string `yaml:"tun_name,omitempty" json:"tun_name,omitempty"`
	MTU           int    `yaml:"mtu,omitempty" json:"mtu,omitempty"`
	UDPListenPort int    `yaml:"udp_listen_port,omitempty" json:"udp_listen_port,omitempty"`
	Cipher        string `yaml:"cipher,omitempty" json:"cipher,omitempty"`
	// PostQuantum / PQAuth: nil = inherit the main network's values.
	PostQuantum *bool `yaml:"post_quantum,omitempty" json:"post_quantum,omitempty"`
	PQAuth      *bool `yaml:"pq_auth,omitempty" json:"pq_auth,omitempty"`
	// ExitNode: BE an internet exit for this network (e.g. a data-center VPS
	// shared into a guest network as a rentable exit). UseExit/ExitPeer: route
	// THIS device's internet traffic via an exit on this network — this is how
	// a guest network's exit is consumed without trusting it with the main
	// network. Only one network in total may set use_exit.
	ExitNode bool   `yaml:"exit_node,omitempty" json:"exit_node,omitempty"`
	UseExit  bool   `yaml:"use_exit,omitempty" json:"use_exit,omitempty"`
	ExitPeer string `yaml:"exit_peer,omitempty" json:"exit_peer,omitempty"`

	StaticPeers       []string `yaml:"static_peers,omitempty" json:"static_peers,omitempty"`
	RendezvousServers []string `yaml:"rendezvous_servers,omitempty" json:"rendezvous_servers,omitempty"`
	Trackers          []string `yaml:"trackers,omitempty" json:"trackers,omitempty"`

	// Enabled: nil/true = run it. false = keep the profile but don't start it.
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Origin records how this node got the profile: "config", "local" (added
	// via the panel), or "shared" (admin-signed share record).
	Origin string `yaml:"origin,omitempty" json:"origin,omitempty"`
}

func (n *SecondaryNetwork) enabled() bool { return n.Enabled == nil || *n.Enabled }

// netIDFor is the short stable identifier for a network: first 8 hex chars of
// SHA-256(network_name). Used for state dirs, socket suffixes and tun names.
func netIDFor(name string) string {
	h := sha256.Sum256([]byte(name))
	return hex.EncodeToString(h[:4])
}

func (n *SecondaryNetwork) id() string { return netIDFor(n.NetworkName) }

func (n *SecondaryNetwork) tunName() string {
	if n.TunName != "" {
		return n.TunName
	}
	return "apg" + n.id()[:4]
}

// listenPort returns the network's UDP port: explicit config, else a stable
// port derived from the network name in 41000..60999 (deterministic, so the
// NAT mapping and announces stay consistent across restarts).
func (n *SecondaryNetwork) listenPort() int {
	if n.UDPListenPort != 0 {
		return n.UDPListenPort
	}
	h := sha256.Sum256([]byte("apgo-port:" + n.NetworkName))
	return 41000 + int(uint16(h[0])<<8|uint16(h[1]))%20000
}

// --- child / parent role ---------------------------------------------------

// isNetChild reports whether this process is a supervised secondary-network
// instance (it must not spawn its own children or apply share records).
func isNetChild() bool { return os.Getenv("APGO_NET_CHILD") != "" }

// networksBaseDir is where runtime-added and share-received network profiles
// (and each child's generated config + state) live.
func networksBaseDir() string {
	if p := os.Getenv("APGO_NETWORKS_DIR"); p != "" {
		return p
	}
	return "/state/networks"
}

func netProfilePath(id string) string { return filepath.Join(networksBaseDir(), id, "net.yaml") }

// loadStoredNetworks reads every persisted secondary-network profile.
func loadStoredNetworks() []SecondaryNetwork {
	entries, err := os.ReadDir(networksBaseDir())
	if err != nil {
		return nil
	}
	var out []SecondaryNetwork
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile(netProfilePath(e.Name()))
		if err != nil {
			continue
		}
		var n SecondaryNetwork
		if yaml.Unmarshal(data, &n) != nil || n.NetworkName == "" || n.PSK == "" {
			continue
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NetworkName < out[j].NetworkName })
	return out
}

func saveStoredNetwork(n SecondaryNetwork) error {
	dir := filepath.Join(networksBaseDir(), n.id())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := yaml.Marshal(&n)
	if err != nil {
		return err
	}
	return os.WriteFile(netProfilePath(n.id()), data, 0o600)
}

func removeStoredNetwork(name string) {
	_ = os.RemoveAll(filepath.Join(networksBaseDir(), netIDFor(name)))
}

// effectiveNetworks merges config-file networks with persisted ones. A config
// entry wins over a stored profile with the same network_name.
func effectiveNetworks(cfg *ClientConfig) []SecondaryNetwork {
	seen := map[string]bool{}
	var out []SecondaryNetwork
	for _, n := range cfg.Networks {
		if n.NetworkName == "" || n.PSK == "" || seen[n.NetworkName] {
			continue
		}
		if n.Origin == "" {
			n.Origin = "config"
		}
		seen[n.NetworkName] = true
		out = append(out, n)
	}
	for _, n := range loadStoredNetworks() {
		if seen[n.NetworkName] || n.NetworkName == cfg.NetworkName {
			continue
		}
		seen[n.NetworkName] = true
		out = append(out, n)
	}
	return out
}

// --- supervisor ------------------------------------------------------------

type netChild struct {
	net      SecondaryNetwork
	cmd      *exec.Cmd
	stopping bool
	started  time.Time
	restarts int
	lastErr  string
}

var (
	supMu       sync.Mutex
	supChildren = map[string]*netChild{} // net id -> child
	supParent   *ClientConfig            // main network's loaded config
)

// startNetSupervisor launches (and keeps launching) one child client per
// enabled secondary network. No-op in child processes.
func startNetSupervisor(cfg *ClientConfig) {
	if isNetChild() {
		return
	}
	supMu.Lock()
	supParent = cfg
	supMu.Unlock()
	reconcileNetworks()
}

// reconcileNetworks aligns running children with the desired set. Safe to call
// from control handlers and share-record application.
func reconcileNetworks() {
	supMu.Lock()
	defer supMu.Unlock()
	if supParent == nil || isNetChild() {
		return
	}
	desired := map[string]SecondaryNetwork{}
	exitClaimed := supParent.UseExit
	for _, n := range effectiveNetworks(supParent) {
		if !n.enabled() {
			continue
		}
		if n.UseExit {
			if exitClaimed {
				log.Printf("[multinet] network %q also sets use_exit — DISABLED there (only one network can own the default route)", n.NetworkName)
				n.UseExit = false
			} else {
				exitClaimed = true
			}
		}
		desired[n.id()] = n
	}
	// Stop children that are no longer wanted.
	for id, c := range supChildren {
		if _, ok := desired[id]; !ok {
			c.stopping = true
			if c.cmd != nil && c.cmd.Process != nil {
				_ = c.cmd.Process.Kill()
			}
			delete(supChildren, id)
			log.Printf("[multinet] stopped network %q", c.net.NetworkName)
		}
	}
	// Start newly wanted ones.
	for id, n := range desired {
		if _, ok := supChildren[id]; ok {
			continue
		}
		c := &netChild{net: n}
		supChildren[id] = c
		go superviseChild(c)
		log.Printf("[multinet] starting network %q (id %s, tun %s, port %d)", n.NetworkName, id, n.tunName(), n.listenPort())
	}
}

// superviseChild runs one secondary-network client process, restarting it with
// backoff until it is no longer desired.
func superviseChild(c *netChild) {
	backoff := 2 * time.Second
	for {
		supMu.Lock()
		if c.stopping || supChildren[c.net.id()] != c {
			supMu.Unlock()
			return
		}
		cmd, err := buildChildCmd(supParent, c.net)
		if err == nil {
			err = cmd.Start()
		}
		if err != nil {
			c.lastErr = err.Error()
			supMu.Unlock()
			log.Printf("[multinet] network %q: cannot start child: %v", c.net.NetworkName, err)
			time.Sleep(backoff)
			if backoff < time.Minute {
				backoff *= 2
			}
			continue
		}
		c.cmd = cmd
		c.started = time.Now()
		supMu.Unlock()
		werr := cmd.Wait()
		supMu.Lock()
		stopping := c.stopping || supChildren[c.net.id()] != c
		if werr != nil {
			c.lastErr = werr.Error()
		}
		c.restarts++
		supMu.Unlock()
		if stopping {
			return
		}
		// A child that ran for a while earns a fresh backoff.
		if time.Since(c.started) > time.Minute {
			backoff = 2 * time.Second
		}
		log.Printf("[multinet] network %q exited (%v) — restarting in %v", c.net.NetworkName, werr, backoff)
		time.Sleep(backoff)
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

// buildChildCmd writes the child's config file and prepares its process with a
// scrubbed, per-network environment.
func buildChildCmd(parent *ClientConfig, n SecondaryNetwork) (*exec.Cmd, error) {
	id := n.id()
	dir := filepath.Join(networksBaseDir(), id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	cc := childConfig(parent, n)
	data, err := yaml.Marshal(cc)
	if err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(dir, "client.yaml")
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Scrub every env var that would override the generated config, then set
	// the per-network ones. The child inherits everything else (PATH, LOG_FILE…).
	drop := map[string]bool{
		"NETWORK_NAME": true, "PSK": true, "OVERLAY_CIDR": true, "OVERLAY_ADDRESS": true,
		"EXIT_NODE": true, "USE_EXIT": true, "EXIT_PEER": true, "NODE_KEY_FILE": true,
		"POST_QUANTUM": true, "PQ_AUTH": true, "RENDEZVOUS_SERVERS": true,
		"CLIENT_CONFIG": true, "CONTROL_SOCKET": true, "APGO_NET_CHILD": true,
		"POLICY_FILE": true, "NETCONFIG_FILE": true, "REVOCATIONS_FILE": true,
		"PROVISIONS_FILE": true, "APPROVALS_FILE": true, "NODE_SETTINGS_FILE": true,
		"SEALED_ADMIN_KEY_FILE": true, "ADMIN_PUBKEY_FILE": true, "NETSHARES_FILE": true,
		"SETUP_FILE": true, "APGO_NETWORKS_DIR": true,
	}
	var env []string
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i > 0 && drop[kv[:i]] {
			continue
		}
		env = append(env, kv)
	}
	env = append(env,
		"APGO_NET_CHILD="+id,
		"CLIENT_CONFIG="+cfgPath,
		"POLICY_FILE="+filepath.Join(dir, "policy.json"),
		"NETCONFIG_FILE="+filepath.Join(dir, "netconfig.json"),
		"REVOCATIONS_FILE="+filepath.Join(dir, "revocations.json"),
		"PROVISIONS_FILE="+filepath.Join(dir, "provisions.json"),
		"APPROVALS_FILE="+filepath.Join(dir, "approvals.json"),
		"NODE_SETTINGS_FILE="+filepath.Join(dir, "nodesettings.json"),
		"SEALED_ADMIN_KEY_FILE="+filepath.Join(dir, "sealed-admin.json"),
		"ADMIN_PUBKEY_FILE="+filepath.Join(dir, "admin.pub"),
		"SETUP_FILE="+filepath.Join(dir, "setup.json"),
	)
	if sock := childControlSocket(id); sock != "" {
		env = append(env, "CONTROL_SOCKET="+sock)
	}
	cmd.Env = env

	// Seed the child's admin trust from the parent so the SAME admin key
	// governs the secondary network (approvals, revocations, shares) without
	// waiting for gossip: the network owner's panel is the root of trust for
	// both. Best-effort; an existing file is left alone.
	if pub := adminPubBytes(); len(pub) > 0 {
		p := filepath.Join(dir, "admin.pub")
		if _, err := os.Stat(p); err != nil {
			_ = os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(pub)), 0o600)
		}
	}
	sealedMu.Lock()
	blob := append([]byte(nil), sealedBlob...)
	sealedMu.Unlock()
	if len(blob) > 0 {
		p := filepath.Join(dir, "sealed-admin.json")
		if _, err := os.Stat(p); err != nil {
			_ = os.WriteFile(p, blob, 0o600)
		}
	}
	return cmd, nil
}

// childControlSocket is the child's control socket path: "<main socket>.<id>",
// so an admin panel that knows the main socket can reach every network.
func childControlSocket(id string) string {
	main := os.Getenv("CONTROL_SOCKET")
	if main == "" {
		return ""
	}
	return main + "." + id
}

// childConfig derives the child's full ClientConfig from its network profile,
// inheriting the main network's transport settings where unset.
func childConfig(parent *ClientConfig, n SecondaryNetwork) *ClientConfig {
	inherit := func(v *bool, d bool) bool {
		if v == nil {
			return d
		}
		return *v
	}
	mtu := n.MTU
	if mtu == 0 {
		mtu = parent.Tun.MTU
	}
	if mtu == 0 {
		mtu = 1280
	}
	cipher := n.Cipher
	if cipher == "" {
		cipher = parent.Cipher
	}
	cc := &ClientConfig{
		NetworkName:                n.NetworkName,
		NodePrivateKey:             parent.NodePrivateKey, // one device identity everywhere
		PSK:                        n.PSK,
		FriendlyName:               parent.FriendlyName,
		OverlayCIDR:                n.OverlayCIDR,
		Tun:                        TunConfig{Name: n.tunName(), MTU: mtu},
		UDPListenPort:              n.listenPort(),
		STUNServers:                parent.STUNServers,
		AnnounceOnlyOnIPChange:     parent.AnnounceOnlyOnIPChange,
		Trackers:                   n.Trackers,
		TrackerListFile:            parent.TrackerListFile,
		RendezvousServers:          n.RendezvousServers,
		MinAnnounceIntervalSeconds: parent.MinAnnounceIntervalSeconds,
		Compression:                parent.Compression,
		Cipher:                     cipher,
		PostQuantum:                inherit(n.PostQuantum, parent.PostQuantum),
		PQAuth:                     inherit(n.PQAuth, parent.PQAuth),
		PortPrediction:             parent.PortPrediction,
		IPv6:                       parent.IPv6,
		StaticPeers:                n.StaticPeers,
		TrackerMode:                parent.TrackerMode,
		KeepaliveSeconds:           parent.KeepaliveSeconds,
		ExitNode:                   n.ExitNode,
		UseExit:                    n.UseExit,
		ExitPeer:                   n.ExitPeer,
	}
	return cc
}

// --- control API -----------------------------------------------------------

// netView is the JSON view of one network for the admin panels.
type netView struct {
	ID            string `json:"id"`
	NetworkName   string `json:"network_name"`
	OverlayCIDR   string `json:"overlay_cidr"`
	Main          bool   `json:"main"`
	Enabled       bool   `json:"enabled"`
	Running       bool   `json:"running"`
	Origin        string `json:"origin,omitempty"`
	ExitNode      bool   `json:"exit_node"`
	UseExit       bool   `json:"use_exit"`
	ExitPeer      string `json:"exit_peer,omitempty"`
	Tun           string `json:"tun,omitempty"`
	UDPListenPort int    `json:"udp_listen_port,omitempty"`
	ControlSocket string `json:"control_socket,omitempty"`
	Restarts      int    `json:"restarts,omitempty"`
	LastError     string `json:"last_error,omitempty"`
}

// nextFreeGuestCIDR proposes an unused /24 for a new network: 10.22.<x>.0/24,
// walking up from the main network's third octet.
func nextFreeGuestCIDR(cfg *ClientConfig) string {
	used := map[string]bool{cfg.OverlayCIDR: true}
	for _, n := range effectiveNetworks(cfg) {
		used[n.OverlayCIDR] = true
	}
	base := net.ParseIP("10.22.56.0")
	if _, ipnet, err := net.ParseCIDR(cfg.OverlayCIDR); err == nil && ipnet.IP.To4() != nil {
		base = ipnet.IP.To4()
	}
	b := append(net.IP(nil), base.To4()...)
	for i := 0; i < 200; i++ {
		b[2]++
		cand := fmt.Sprintf("%d.%d.%d.0/24", b[0], b[1], b[2])
		if !used[cand] {
			return cand
		}
	}
	return "10.99.99.0/24"
}

// registerMultinetAPI adds the multi-network endpoints to the control server.
// Child processes only get /api/networks (reporting themselves), keeping the
// management surface on the main instance.
func registerMultinetAPI(mux *http.ServeMux) {
	mux.HandleFunc("/api/networks", func(w http.ResponseWriter, r *http.Request) {
		var out []netView
		supMu.Lock()
		parent := supParent
		if parent != nil {
			out = append(out, netView{
				ID: "main", NetworkName: parent.NetworkName, OverlayCIDR: parent.OverlayCIDR,
				Main: true, Enabled: true, Running: true,
				ExitNode: parent.ExitNode, UseExit: useExit, ExitPeer: parent.ExitPeer,
				Tun: parent.Tun.Name, UDPListenPort: parent.UDPListenPort,
			})
			for _, n := range effectiveNetworks(parent) {
				v := netView{
					ID: n.id(), NetworkName: n.NetworkName, OverlayCIDR: n.OverlayCIDR,
					Enabled: n.enabled(), Origin: n.Origin,
					ExitNode: n.ExitNode, UseExit: n.UseExit, ExitPeer: n.ExitPeer,
					Tun: n.tunName(), UDPListenPort: n.listenPort(),
					ControlSocket: childControlSocket(n.id()),
				}
				if c, ok := supChildren[n.id()]; ok {
					v.Running = c.cmd != nil && !c.stopping
					v.Restarts = c.restarts
					v.LastError = c.lastErr
				}
				out = append(out, v)
			}
		}
		supMu.Unlock()
		writeJSON(w, http.StatusOK, out)
	})

	if isNetChild() {
		return
	}

	// Add a network: mode "join" (credentials in hand) or "create" (this node
	// is the initiator — a fresh name + PSK are generated and returned so the
	// panel can render an invite).
	mux.HandleFunc("/api/network-add", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Mode string `json:"mode"` // "join" | "create"
			SecondaryNetwork
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		supMu.Lock()
		parent := supParent
		supMu.Unlock()
		if parent == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		n := req.SecondaryNetwork
		switch req.Mode {
		case "create":
			if n.NetworkName == "" {
				n.NetworkName = fmt.Sprintf("%s.guest-%s", parent.NetworkName, netIDFor(generatePSK()))
			}
			if n.PSK == "" {
				n.PSK = generatePSK()
			}
		case "join":
			if n.NetworkName == "" || n.PSK == "" {
				http.Error(w, "join needs network_name and psk", http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, `mode must be "join" or "create"`, http.StatusBadRequest)
			return
		}
		if n.NetworkName == parent.NetworkName {
			http.Error(w, "that is already this node's main network", http.StatusBadRequest)
			return
		}
		if n.OverlayCIDR == "" {
			n.OverlayCIDR = nextFreeGuestCIDR(parent)
		}
		if _, _, err := net.ParseCIDR(n.OverlayCIDR); err != nil {
			http.Error(w, "bad overlay_cidr", http.StatusBadRequest)
			return
		}
		if n.Origin == "" {
			n.Origin = "local"
		}
		if err := saveStoredNetwork(n); err != nil {
			http.Error(w, "persist: "+err.Error(), http.StatusInternalServerError)
			return
		}
		reconcileNetworks()
		writeJSON(w, http.StatusOK, n)
	})

	// Full profile of one secondary network, INCLUDING its PSK — the panel
	// needs it to seal a share to a target device and to render invite QRs.
	// Same exposure class as /api/join-info (local admin socket only).
	mux.HandleFunc("/api/network-profile", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		supMu.Lock()
		parent := supParent
		supMu.Unlock()
		if parent == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		for _, n := range effectiveNetworks(parent) {
			if n.NetworkName == name {
				writeJSON(w, http.StatusOK, n)
				return
			}
		}
		http.Error(w, "unknown network", http.StatusNotFound)
	})

	mux.HandleFunc("/api/network-remove", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			NetworkName string `json:"network_name"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.NetworkName == "" {
			http.Error(w, "network_name required", http.StatusBadRequest)
			return
		}
		removeStoredNetwork(req.NetworkName)
		reconcileNetworks()
		writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
	})

	// Update a stored network profile in place (enable/disable, exit settings).
	mux.HandleFunc("/api/network-set", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			NetworkName string  `json:"network_name"`
			Enabled     *bool   `json:"enabled,omitempty"`
			UseExit     *bool   `json:"use_exit,omitempty"`
			ExitPeer    *string `json:"exit_peer,omitempty"`
			ExitNode    *bool   `json:"exit_node,omitempty"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.NetworkName == "" {
			http.Error(w, "network_name required", http.StatusBadRequest)
			return
		}
		var target *SecondaryNetwork
		for _, n := range loadStoredNetworks() {
			if n.NetworkName == req.NetworkName {
				nn := n
				target = &nn
				break
			}
		}
		if target == nil {
			http.Error(w, "unknown network (config-file networks are edited in the config)", http.StatusNotFound)
			return
		}
		if req.Enabled != nil {
			target.Enabled = req.Enabled
		}
		if req.UseExit != nil {
			target.UseExit = *req.UseExit
		}
		if req.ExitPeer != nil {
			target.ExitPeer = *req.ExitPeer
		}
		if req.ExitNode != nil {
			target.ExitNode = *req.ExitNode
		}
		if err := saveStoredNetwork(*target); err != nil {
			http.Error(w, "persist: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Restart the child so the new profile applies.
		supMu.Lock()
		if c, ok := supChildren[target.id()]; ok {
			c.stopping = true
			if c.cmd != nil && c.cmd.Process != nil {
				_ = c.cmd.Process.Kill()
			}
			delete(supChildren, target.id())
		}
		supMu.Unlock()
		reconcileNetworks()
		writeJSON(w, http.StatusOK, target)
	})
}
