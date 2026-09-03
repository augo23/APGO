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
	"encoding/base64"
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
	NetworkName       string   `json:"network_name"`
	PSK               string   `json:"psk"`
	FriendlyName      string   `json:"friendly_name"` // human label shown to peers
	OverlayIP         string   `json:"overlay_ip"`    // bare host, e.g. 10.22.55.30
	OverlayCIDR       string   `json:"overlay_cidr"`  // e.g. 10.22.55.0/24
	Trackers          []string `json:"trackers"`
	RendezvousServers []string `json:"rendezvous_servers"`
	STUNServers       []string `json:"stun_servers"`
	AdminPubKey       string   `json:"admin_public_key"`
	KeyPath           string   `json:"key_path"`  // writable path for the node key
	UseExit           bool     `json:"use_exit"`  // route ALL traffic via an exit (full VPN)
	ExitPeer          string   `json:"exit_peer"` // pin ONE exit (overlay IP / name / key); "" = fastest
	UDPPort           int      `json:"udp_listen_port"`
	Cipher            string   `json:"cipher"`
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
	go func() {
		t := time.NewTicker(30 * time.Second)
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

// --- admission control from the phone ---------------------------------------
//
// gomobile only exports a narrow set of types across the language boundary
// (strings, ints, bools, errors), so these are deliberately string-in /
// error-out rather than passing structs around.

// AdminKeyAvailable reports whether this device holds the network admin key
// and can therefore sign approvals given the password.
//
// The app should call this before showing an Approve button: the key arrives
// by mesh gossip, so on a freshly installed phone it is briefly false and then
// becomes true on its own. A button that appears and then fails is worse than
// one that appears a few seconds late.
func AdminKeyAvailable() bool { return adminKeyAvailable() }

// AdmissionRequired reports whether this network gates new devices at all
// (i.e. it has an admin key). When false there is nothing to approve and the
// app should not show any of this.
func AdmissionRequired() bool { return admissionRequired() }

// SelfApproved reports whether THIS device is approved on the network.
func SelfApproved() bool { return selfApproved() }

// SelfPubKey returns this device's own static key (base64), or "" when the
// overlay is not running.
func SelfPubKey() string {
	bridgeMu.Lock()
	up := running
	bridgeMu.Unlock()
	if !up {
		return ""
	}
	return base64.StdEncoding.EncodeToString(gKP.pub[:])
}

// ApproveDevice approves (or denies) a peer by its base64 static key, using the
// network admin password. The signed record is applied locally and flooded to
// the mesh, exactly as the desktop and container panels do it.
//
// action is "approve" or "deny"; anything else is treated as "approve" so a
// caller passing "" gets the safe, obvious meaning rather than a silent no-op.
func ApproveDevice(password, pubKeyB64, action string) error {
	if pubKeyB64 == "" {
		return errors.New("no device key given")
	}
	if password == "" {
		return errors.New("network admin password required")
	}
	if action != "approve" && action != "deny" {
		action = "approve"
	}
	if !admissionRequired() {
		return errors.New("this network has no admin key, so devices do not need approval")
	}
	rec, err := signApproval(password, pubKeyB64, action)
	if err != nil {
		return err
	}
	return applyAndGossipApproval(rec)
}

// PendingAddress returns a new overlay address an admin has assigned this device
// that will take effect on the next (re)connect, or "" if none. The app polls
// this to warn the user and re-establish the tunnel.
func PendingAddress() string {
	return getPendingAddress()
}

func toClientConfig(mc mobileConfig) *ClientConfig {
	cfg := &ClientConfig{
		NetworkName:       mc.NetworkName,
		PSK:               mc.PSK,
		FriendlyName:      mc.FriendlyName,
		OverlayCIDR:       mc.OverlayCIDR,
		UDPListenPort:     mc.UDPPort,
		STUNServers:       mc.STUNServers,
		Trackers:          mc.Trackers,
		RendezvousServers: mc.RendezvousServers,
		Cipher:            mc.Cipher,
		KeepaliveSeconds:  mc.KeepaliveSeconds,
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
