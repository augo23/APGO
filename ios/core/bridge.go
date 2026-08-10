// Package overlaymobile is the gomobile-bindable entry point for the iOS app.
// The NEPacketTunnelProvider extension creates the tunnel, configures the
// overlay IP/route, and owns its file descriptor; it passes that fd (and the
// JSON config) to Start, which runs the full APGO overlay core (vendored in
// this package) over it.
//
// Build the framework from ios/:
//
//	gomobile bind -target=ios -o ios/Overlaymobile.xcframework ./core
//
// The generated Swift API is: OverlaymobileStart(fd, json, &err), OverlaymobileStop().
package overlaymobile

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// mobileConfig is the JSON the app passes in providerConfiguration.
type mobileConfig struct {
	NetworkName  string   `json:"network_name"`
	PSK          string   `json:"psk"`
	FriendlyName string   `json:"friendly_name"` // human label shown to peers
	OverlayIP    string   `json:"overlay_ip"`    // bare host, e.g. 10.22.55.30
	OverlayCIDR  string   `json:"overlay_cidr"`  // e.g. 10.22.55.0/24
	Trackers          []string `json:"trackers"`
	RendezvousServers []string `json:"rendezvous_servers"`
	// RendezvousAuth: credential for servers that require one. "user:pass"
	// (with a colon) = HTTP Basic; anything else = Bearer token. Blank = none.
	RendezvousAuth string   `json:"rendezvous_auth"`
	STUNServers    []string `json:"stun_servers"`
	AdminPubKey string   `json:"admin_public_key"`
	KeyPath     string   `json:"key_path"` // writable path for the node key
	UseExit     bool     `json:"use_exit"`  // route ALL traffic via an exit (full VPN)
	ExitPeer    string   `json:"exit_peer"` // pin ONE exit (overlay IP / name / key); "" = fastest
	UDPPort     int      `json:"udp_listen_port"`
	Cipher      string   `json:"cipher"`
	// KeepaliveSeconds tunes the NAT keepalive (0 = default 10s).
	KeepaliveSeconds int `json:"keepalive_seconds"`
	// Quantum-safe settings are pointers so an ABSENT field defaults to ON —
	// older app builds that don't send them still get post-quantum protection.
	PostQuantum *bool `json:"post_quantum"` // hybrid ML-KEM-768 layer (default on)
	PQAuth      *bool `json:"pq_auth"`      // XXpsk0 handshake auth (default on)
	// IPv6 dual-stack transport. Pointer so an absent field defaults to ON
	// (older app builds that don't send it still get IPv6).
	IPv6 *bool `json:"ipv6"`
	// PortPrediction forces symmetric-NAT port prediction on. Pointer so an
	// absent field defaults to ON, matching the desktop and container configs.
	// The core also enables it by itself once it classifies the NAT as
	// symmetric; this field was missing entirely before, so the phone could
	// never turn it on and stayed RELAYED to every NATed peer behind such a
	// router.
	PortPrediction *bool `json:"port_prediction"`
	// UtunHeader tells the bridge the tun fd carries the 4-byte AF protocol
	// header (raw iOS utun). iOS sets this true; Android (VpnService, raw L3)
	// leaves it false/absent. Without it the iOS data path is broken (see
	// utunwrap.go).
	UtunHeader bool `json:"utun_header"`
	// ManageTrackers marks Trackers as the user-edited, AUTHORITATIVE list
	// (the app's tracker editor). It is persisted to the managed trackers.txt
	// — same semantics as the desktop app — so REMOVALS stick instead of the
	// defaults being unioned back in. An empty list with ManageTrackers=true
	// deletes the managed file, i.e. resets to the curated defaults.
	ManageTrackers bool `json:"manage_trackers"`
	// WipeStateNonce, when non-empty and DIFFERENT from the last nonce this
	// device applied, wipes all persisted overlay state (node key, provisions,
	// approvals, admin key material, netconfig, policy) before starting.
	//
	// Why: "Delete this network" in the app only removes the UI profile — the
	// state dir lives in the tunnel extension's container, which the app cannot
	// touch. On rejoin, adoptSelfProvisionAtStartup re-applied the STALE
	// admin-assigned IP from the old provisions.json, so the core announced an
	// overlay IP the OS tunnel wasn't configured with and the device got no
	// traffic until an admin re-provisioned it. The app sets a fresh nonce when
	// the user deletes a network; the nonce guard makes the wipe one-shot, so
	// OS-initiated tunnel restarts reusing the same saved config don't wipe
	// freshly re-joined state.
	WipeStateNonce string `json:"wipe_state_nonce"`
}

var (
	bridgeMu sync.Mutex
	running  bool
	stopCh   chan struct{}
	tunFile  *os.File
)

// Start runs the overlay over the tunnel file descriptor the platform provides.
// It returns immediately (the overlay runs on its own goroutines). Safe to call
// once; call Stop before starting again.
func Start(tunFD int, configJSON string) error {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	if running {
		return errors.New("overlay already running")
	}

	var mc mobileConfig
	if err := json.Unmarshal([]byte(configJSON), &mc); err != nil {
		return err
	}
	if mc.NetworkName == "" || mc.PSK == "" {
		return errors.New("network_name and psk are required")
	}

	cfg := toClientConfig(mc)

	// One-shot state wipe requested by the app (user deleted / forgot this
	// network). Must run BEFORE the env paths below are read by run().
	if mc.WipeStateNonce != "" {
		maybeWipeState(filepath.Dir(cfg.NodePrivateKey), mc.WipeStateNonce)
	}

	// loadAdminPublicKey reads ADMIN_PUBLIC_KEY from the environment; set it so
	// the app-provided admin key is trusted from the first packet.
	if mc.AdminPubKey != "" {
		_ = os.Setenv("ADMIN_PUBLIC_KEY", mc.AdminPubKey)
	}
	// Persist admin-assigned provisions (IP/name) next to the node key so an
	// assigned overlay IP is adopted on the next reconnect, and seeded admin keys
	// survive restarts.
	if dir := filepath.Dir(cfg.NodePrivateKey); dir != "" {
		_ = os.Setenv("PROVISIONS_FILE", filepath.Join(dir, "provisions.json"))
		_ = os.Setenv("ADMIN_PUBKEY_FILE", filepath.Join(dir, "admin-pubkey"))
		// Admission approvals, network-config rotation, and managed trackers.
		_ = os.Setenv("APPROVALS_FILE", filepath.Join(dir, "approvals.json"))
		_ = os.Setenv("NETCONFIG_FILE", filepath.Join(dir, "netconfig.json"))
		_ = os.Setenv("TRACKERS_FILE", filepath.Join(dir, "trackers.txt"))
		_ = os.Setenv("POLICY_FILE", filepath.Join(dir, "policy.json"))
	}

	// User-managed tracker list (the app's Settings editor): persist it to the
	// managed trackers.txt, which loadTrackerList treats as authoritative — the
	// exact behavior of the desktop app's tracker manager. An empty managed
	// list resets to the curated defaults.
	if mc.ManageTrackers {
		gTrackerFile = trackerFilePath()
		if len(mc.Trackers) > 0 {
			_ = saveTrackers(mc.Trackers)
		} else {
			_ = os.Remove(gTrackerFile)
		}
	}

	// Wrap the OS tunnel fd. Android's VpnService fd is raw L3 (IPv4), but a raw
	// iOS utun fd prefixes every packet with a 4-byte AF header — the app sets
	// utun_header=true in that case so we strip/prepend it (see utunwrap.go).
	// Getting this wrong makes the tunnel form sessions but move no data.
	f := os.NewFile(uintptr(tunFD), "tun")
	if f == nil {
		return errors.New("invalid tun fd")
	}
	var tun io.ReadWriteCloser = f
	if mc.UtunHeader {
		tun = newUtunRW(f)
	}

	stop := make(chan struct{})
	stopCh = stop
	tunFile = f
	running = true

	// MEMORY GUARD. iOS network extensions are hard-capped at ~50 MB — the OS
	// kills the process with EXC_RESOURCE (high watermark memory limit
	// exceeded) the instant RSS crosses it. Go's default GC (GOGC=100) lets
	// the heap DOUBLE between collections, so even a ~20 MB live heap spikes
	// past the cap under handshake/PQ bursts. Cap the runtime's footprint
	// well under the limit and collect eagerly; the extra GC CPU is
	// negligible next to the crypto. Also return freed pages to the OS
	// periodically — iOS judges the extension by RSS, and Go's background
	// scavenger is too lazy for a 50 MB budget. (Android has no such cap,
	// but the same tuning is a safe footprint reduction there.)
	debug.SetMemoryLimit(30 << 20) // 30 MB ceiling for the whole Go runtime
	debug.SetGCPercent(20)
	// FreeOSMemory is a full STOP-THE-WORLD GC plus a scavenge — it is what
	// keeps the extension inside iOS's hard memory cap, but it is genuinely
	// expensive CPU (and therefore battery) to run every 30 seconds forever.
	// Every 2 minutes holds the footprint just as well in practice: the cap
	// is about a ceiling, not about instantaneous reclaim, and the runtime's
	// own GC (SetGCPercent(20) above) is doing the real work between passes.
	go func() {
		t := time.NewTicker(2 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				debug.FreeOSMemory()
			}
		}
	}()

	go func() {
		if err := run(tun, cfg, stop); err != nil {
			bridgeMu.Lock()
			running = false
			bridgeMu.Unlock()
		}
	}()
	return nil
}

// Stop tears the overlay down and closes the tunnel.
func Stop() {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	if !running {
		return
	}
	if stopCh != nil {
		close(stopCh)
		stopCh = nil
	}
	if tunFile != nil {
		_ = tunFile.Close()
		tunFile = nil
	}
	running = false
}

// Running reports whether the overlay is active (for the app's status UI).
func Running() bool {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	return running
}

// PeersJSON returns the current peer/session list as a JSON array (SessionInfo
// shape: overlay_ip, name, key_fp, established, post_quantum, last_seen_unix, …).
// The app renders its live "Peers" list from this — on iOS via the tunnel
// extension's sendProviderMessage, on Android by calling this directly (the
// VpnService shares the process, hence the same Go runtime + GlobalSessions).
func PeersJSON() string {
	bridgeMu.Lock()
	up := running
	bridgeMu.Unlock()
	if !up || GlobalSessions == nil {
		return "[]"
	}
	b, err := json.Marshal(GlobalSessions.Snapshot())
	if err != nil {
		return "[]"
	}
	return string(b)
}

// PendingAddress returns a new overlay address an admin has assigned this device
// that will take effect on the next (re)connect, or "" if none. The app polls
// this to warn the user and re-establish the tunnel.
func PendingAddress() string {
	return getPendingAddress()
}

// NetworkStatusJSON reports this device's own transport situation:
//
//	{"nat_type":"symmetric","public_endpoint":"1.2.3.4:5678","ipv6":false,
//	 "candidates":"1.2.3.4:5678,192.168.1.9:6969"}
//
// This is the fact that explains "why is this peer always relayed", and the
// phone was the one device that never showed it. NAT type decides what is
// even POSSIBLE: two symmetric NATs have no predictable port on either side,
// so hole punching cannot work between them no matter how often it retries —
// that pair is permanently relayed, and no setting will change it. A phone on
// carrier CGNAT is routinely symmetric, which is why it can behave completely
// differently from a laptop sitting next to it on the same Wi-Fi.
func NetworkStatusJSON() string {
	bridgeMu.Lock()
	up := running
	bridgeMu.Unlock()
	resp := map[string]any{
		"nat_type": "", "public_endpoint": "", "ipv6": false, "candidates": "",
	}
	if !up {
		b, _ := json.Marshal(resp)
		return string(b)
	}
	resp["nat_type"] = natTypeLabel()
	resp["public_endpoint"] = currentPublicEndpoint()
	resp["ipv6"] = hasGlobalIPv6()
	resp["candidates"] = myConnectCandidates()
	b, err := json.Marshal(resp)
	if err != nil {
		return `{"nat_type":"","public_endpoint":"","ipv6":false,"candidates":""}`
	}
	return string(b)
}

// ExitsJSON returns the live full-VPN outproxy view so the apps can show WHY
// "no exit is reachable" instead of a dead end: every exit the mesh has
// advertised to this device, with reachability, latency, and which one is
// selected. {"use_exit":bool,"pin":"…","exits":[{"overlay_ip","name","rtt_ms",
// "reachable","selected"},…]} — an empty exits array with use_exit on means NO
// exit announce has arrived here at all (the exit is off, unreachable, or has
// no direct session to this device).
func ExitsJSON() string {
	bridgeMu.Lock()
	up := running
	bridgeMu.Unlock()
	type exitView struct {
		OverlayIP string `json:"overlay_ip"`
		Name      string `json:"name"`
		RttMs     int64  `json:"rtt_ms"`
		Reachable bool   `json:"reachable"`
		Selected  bool   `json:"selected"`
	}
	resp := struct {
		UseExit bool       `json:"use_exit"`
		Pin     string     `json:"pin"`
		Exits   []exitView `json:"exits"`
	}{Exits: []exitView{}}
	if !up || GlobalSessions == nil {
		b, _ := json.Marshal(resp)
		return string(b)
	}
	exitMu.Lock()
	resp.UseExit = useExit
	resp.Pin = exitPin
	type raw struct {
		pub       [32]byte
		addr      *net.UDPAddr
		rttMs     int64
		lastReply time.Time
		selected  bool
	}
	raws := make([]raw, 0, len(exitCandidates))
	for _, e := range exitCandidates {
		raws = append(raws, raw{pub: e.pub, addr: e.addr, rttMs: e.rttMs,
			lastReply: e.lastReply, selected: e == selectedExit})
	}
	exitMu.Unlock()
	for _, r := range raws {
		v := exitView{
			OverlayIP: resolvePeerIP(r.pub),
			Name:      resolvePeerName(r.pub),
			RttMs:     -1,
			Selected:  r.selected,
		}
		if !r.lastReply.IsZero() {
			v.RttMs = r.rttMs
		}
		if s := GlobalSessions.GetByAddr(r.addr); s != nil && s.Established() &&
			time.Since(r.lastReply) <= 90*time.Second {
			v.Reachable = true
		}
		resp.Exits = append(resp.Exits, v)
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return `{"use_exit":false,"pin":"","exits":[]}`
	}
	return string(b)
}

func toClientConfig(mc mobileConfig) *ClientConfig {
	cfg := &ClientConfig{
		NetworkName:   mc.NetworkName,
		PSK:           mc.PSK,
		FriendlyName:  mc.FriendlyName,
		OverlayCIDR:   mc.OverlayCIDR,
		UDPListenPort: mc.UDPPort,
		STUNServers:       mc.STUNServers,
		Trackers:          mc.Trackers,
		RendezvousServers: mc.RendezvousServers,
		RendezvousAuth:    mc.RendezvousAuth,
		Cipher:           mc.Cipher,
		KeepaliveSeconds: mc.KeepaliveSeconds,
		// Quantum-safe by default: absent flags mean ON.
		PostQuantum: mc.PostQuantum == nil || *mc.PostQuantum,
		PQAuth:      mc.PQAuth == nil || *mc.PQAuth,
		IPv6:        mc.IPv6 == nil || *mc.IPv6, // default ON
		// Symmetric-NAT port prediction, default ON. The core also enables it
		// on its own once it classifies the NAT as symmetric.
		PortPrediction: mc.PortPrediction == nil || *mc.PortPrediction,
		Compression:    true,
		UseExit:        mc.UseExit,
		ExitPeer:       mc.ExitPeer,
		NodePrivateKey: keyPathOrDefault(mc.KeyPath),
	}
	if cfg.OverlayCIDR == "" {
		cfg.OverlayCIDR = "10.22.55.0/24"
	}
	// Turn the bare overlay IP into a CIDR (mask inherited from overlay_cidr).
	if mc.OverlayIP != "" {
		ones := 24
		if _, ipnet, err := net.ParseCIDR(cfg.OverlayCIDR); err == nil {
			ones, _ = ipnet.Mask.Size()
		}
		cfg.Tun.AddressCIDR = mc.OverlayIP + "/" + strconv.Itoa(ones)
	}
	if len(cfg.STUNServers) == 0 {
		cfg.STUNServers = []string{"stun.l.google.com:19302", "stun1.l.google.com:19302"}
	}
	return cfg
}

// maybeWipeState deletes every piece of persisted overlay state in dir if
// nonce differs from the last nonce already applied (recorded in .wipe-nonce).
// Wiping the node key gives the device a FRESH identity on rejoin — required
// when the old key was revoked network-side after a "forget", and it makes the
// derived overlay IP consistent with what peers will learn.
func maybeWipeState(dir, nonce string) {
	if dir == "" || dir == "." {
		return
	}
	marker := filepath.Join(dir, ".wipe-nonce")
	if b, err := os.ReadFile(marker); err == nil && strings.TrimSpace(string(b)) == nonce {
		return // already applied — don't wipe freshly re-joined state
	}
	for _, f := range []string{
		"node.key",
		"provisions.json",
		"approvals.json",
		"admin-pubkey",
		"admin-key-sealed.json",
		"netconfig.json",
		"policy.json",
		"revocations.json",
		"trackers.txt",
		"node-settings.json",
	} {
		_ = os.Remove(filepath.Join(dir, f))
	}
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(marker, []byte(nonce), 0o600)
}

// ResetState wipes all persisted overlay state (node key, provisions, admin
// key material, …) in the directory containing keyPath — or the default state
// dir when keyPath is "". Exposed to the apps for an explicit "forget
// everything about this network" action while the overlay is stopped.
func ResetState(keyPath string) {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	if running {
		return // never yank the key out from under a live overlay
	}
	dir := filepath.Dir(keyPathOrDefault(keyPath))
	// Force the wipe regardless of any previously recorded nonce.
	_ = os.Remove(filepath.Join(dir, ".wipe-nonce"))
	maybeWipeState(dir, "reset-"+strconv.FormatInt(time.Now().UnixNano(), 10))
}

func keyPathOrDefault(p string) string {
	p = strings.TrimSpace(p)
	if p != "" {
		return p
	}
	// Fall back to a persistent per-user path if the app didn't supply one.
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dir := home + "/Library/APGO"
		_ = os.MkdirAll(dir, 0o700)
		return dir + "/node.key"
	}
	return os.TempDir() + "/apgo-node.key"
}
