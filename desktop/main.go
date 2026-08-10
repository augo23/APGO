// overlay-desktop is the cross-platform (macOS + Windows) APGO tray app. It
// shows connection status and peer count, lets you enter the network config via
// a local web form, exposes the admin panel, and connects/disconnects the
// native client. Everything here is OS-independent; the small platform layer
// (elevation, native dialogs, browser open, exe name) lives in
// platform_darwin.go / platform_windows.go.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/getlantern/systray"
	"gopkg.in/yaml.v3"
)

var (
	mStatus     *systray.MenuItem
	mPeers      *systray.MenuItem
	mConnect    *systray.MenuItem
	mDisconnect *systray.MenuItem
	mSettings   *systray.MenuItem
	mAdmin      *systray.MenuItem
	mLogin      *systray.MenuItem
	mBoot       *systray.MenuItem
	mQuit       *systray.MenuItem
)

func main() {
	setupLogging()
	systray.Run(onReady, func() {})
}

// opMu serializes the privileged connect/disconnect operations. Without it a
// second Connect (e.g. the login auto-connect racing a user click, or the admin
// panel and the tray both firing) could stack two osascript prompts and two
// clients writing the same pid file / config at once.
var opMu sync.Mutex

// setupLogging sends this app's own log (including recovered-panic traces) to
// ~/.apgo/desktop.log. Inside a .app bundle stderr goes nowhere, so without
// this a crash left no trace to diagnose.
func setupLogging() {
	f, err := os.OpenFile(filepath.Join(appDir(), "desktop.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	log.SetOutput(f)
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("apgo-desktop ")
}

// safeRun runs fn and turns any panic into a logged line + a notification
// instead of a process crash. A menu-bar app is expected to sit running for
// days; a transient panic in one action (a bad osascript result, a nil field
// from a half-written config, a systray hiccup) must not take the whole app
// down — which was the "crashes from time to time" symptom, since NOTHING in
// this app recovered and every action runs in its own goroutine.
func safeRun(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recover] %s panicked: %v\n%s", name, r, debug.Stack())
			notify("APGO hit a problem (" + name + ") but kept running.")
		}
	}()
	fn()
}

// safeGo is safeRun in its own goroutine — the crash-safe replacement for the
// bare `go doThing()` calls scattered across the app.
func safeGo(name string, fn func()) { go safeRun(name, fn) }

func onReady() {
	systray.SetTemplateIcon(iconPNG(), iconPNG())
	systray.SetTooltip("APGO overlay")

	mStatus = systray.AddMenuItem("○ Disconnected", "")
	mStatus.Disable()
	mPeers = systray.AddMenuItem("Peers: —", "")
	mPeers.Disable()
	systray.AddSeparator()
	mConnect = systray.AddMenuItem("Connect", "Join the overlay")
	mDisconnect = systray.AddMenuItem("Disconnect", "Leave the overlay")
	mSettings = systray.AddMenuItem("Settings…", "Network name, PSK, subnet, admin key")
	mAdmin = systray.AddMenuItem("Admin panel…", "Sessions, revoke, logs")
	setupNetworksMenu() // "Networks" submenu: add / switch / save / delete profiles
	mLogin = systray.AddMenuItemCheckbox("Start at login", "Launch APGO and connect when you log in", loginStartEnabled())
	if bootStartSupported() {
		mBoot = systray.AddMenuItemCheckbox("Connect at system startup (no login)",
			"Bring the overlay up at boot, before anyone logs in (installs a system service)", bootStartEnabled())
	}
	systray.AddSeparator()
	mQuit = systray.AddMenuItem("Quit", "")

	startAdminServer()

	// If start-at-login is on and we have a usable config, connect automatically
	// once the tray is up (this run was almost certainly triggered by login).
	if loginStartEnabled() {
		if c := loadConfig(); c.NetworkName != "" && c.PSK != "" {
			safeGo("auto-connect", func() {
				time.Sleep(1500 * time.Millisecond)
				if _, ok := fetchInfo(); !ok { // not already running
					doConnect()
				}
			})
		}
	}

	safeGo("menu loop", loop)
}

func loop() {
	poll := time.NewTicker(2 * time.Second)
	defer poll.Stop()
	safeRun("refreshStatus", refreshStatus)
	// A nil menu item (boot-start unsupported) yields a nil channel, which simply
	// never fires in the select below.
	var bootCh <-chan struct{}
	if mBoot != nil {
		bootCh = mBoot.ClickedCh
	}
	for {
		select {
		case <-mConnect.ClickedCh:
			safeGo("connect", doConnect)
		case <-mDisconnect.ClickedCh:
			safeGo("disconnect", doDisconnect)
		case <-mSettings.ClickedCh:
			safeGo("settings", doSettings)
		case <-mAdmin.ClickedCh:
			safeRun("admin panel", openAdminPanel)
		case <-mLogin.ClickedCh:
			safeRun("start-at-login", toggleLoginStart)
		case <-bootCh:
			safeRun("boot-start", toggleBootStart)
		case <-mQuit.ClickedCh:
			systray.Quit()
			return
		case <-poll.C:
			safeRun("refreshStatus", refreshStatus)
		}
	}
}

// toggleLoginStart flips the OS login item and syncs the menu checkbox.
func toggleLoginStart() {
	enable := !loginStartEnabled()
	if err := setLoginStart(enable); err != nil {
		notify("Couldn't change start-at-login: " + err.Error())
		return
	}
	if enable {
		mLogin.Check()
		notify("APGO will start and connect when you log in.")
	} else {
		mLogin.Uncheck()
		notify("APGO will no longer start at login.")
	}
}

// toggleBootStart installs or removes the boot-time system service that brings
// the overlay up BEFORE any user logs in (macOS LaunchDaemon / Windows
// scheduled task running as SYSTEM). Unlike "Start at login", this connects the
// network at boot without a GUI session; the tray UI still only appears once
// someone logs in, and reflects the already-live connection. Installing needs a
// one-time admin/UAC approval.
func toggleBootStart() {
	if mBoot == nil || !bootStartSupported() {
		return
	}
	enable := !bootStartEnabled()
	if enable {
		if c := loadConfig(); c.NetworkName == "" || c.PSK == "" {
			notify("Set a network name and PSK in Settings before enabling startup connection.")
			return
		}
	}
	if err := setBootStart(enable); err != nil {
		notify("Couldn't change startup connection: " + err.Error())
		return
	}
	if enable {
		mBoot.Check()
		notify("APGO will connect at system startup, before login.")
	} else {
		mBoot.Uncheck()
		notify("APGO will no longer connect at startup.")
	}
}

// doAddNetwork starts a BRAND-NEW network: it first snapshots the current
// network as its own switchable profile (so it isn't lost), then opens Settings
// with a blank form. Saving writes the new network as the active config and
// registers it as its own profile — i.e. "save and switch to it", with the old
// network still available under the Networks submenu.
func doAddNetwork() {
	_, _ = registerCurrentProfile() // preserve the current network, if named
	if adminAddr == "" {
		openNewNetworkWindow()
		return
	}
	openBrowser("http://" + adminAddr + "/settings?new=1")
}

// --- status --------------------------------------------------------------

func refreshStatus() {
	info, ok := fetchInfo()
	if ok {
		// A client parked in setup mode (started before the network was
		// configured) answers /api/info too — it is NOT connected. Showing
		// "● Connected" for it hid the real state and disabled the Connect
		// item, the one action that can un-park it.
		if ns, _ := info["needs_setup"].(bool); ns {
			mStatus.SetTitle("○ Waiting for setup")
			mPeers.SetTitle("Peers: —")
			mConnect.Enable()
			mDisconnect.Enable()
			return
		}
		ip, _ := info["overlay_ip"].(string)
		sess := 0
		if f, ok := info["sessions"].(float64); ok {
			sess = int(f)
		}
		label := "● Connected"
		if ip != "" {
			label += "  " + ip
		}
		mStatus.SetTitle(label)
		mPeers.SetTitle(fmt.Sprintf("Peers: %d", sess))
		mConnect.Disable()
		mDisconnect.Enable()
	} else {
		// "Disconnected" is a guess: it only means WE could not reach the
		// client. Say which, so the case where the client is fine and the app
		// is locked out (root-owned ~/.apgo) is not mistaken for an outage.
		d := controlSocketDiagnosis()
		if strings.Contains(d, "permission denied") || strings.Contains(d, "owned by root") {
			mStatus.SetTitle("⚠ Cannot reach client (permissions)")
		} else if strings.Contains(d, "did not answer") {
			mStatus.SetTitle("⚠ Client not responding")
		} else {
			mStatus.SetTitle("○ Disconnected")
		}
		mStatus.SetTooltip(d)
		mPeers.SetTitle("Peers: —")
		mConnect.Enable()
		mDisconnect.Enable() // allow a forced stop even when we cannot query
	}
}

// controlSocketDiagnosis explains, in one sentence, why the app cannot talk to
// the client — instead of the app saying "connection error" while the client
// is demonstrably alive (phones still list this machine).
//
// Every cause here has been seen in the wild and they are indistinguishable
// from the UI: the socket file missing (client not running), the socket
// present but stale (client died without cleaning up), no permission to
// traverse ~/.apgo (root created it before the installer did, leaving it
// root-owned 0700 — the client then works fine as root while the user's app
// is locked out), or the socket answering too slowly.
func controlSocketDiagnosis() string {
	sock := controlSocket()
	dir := appDir()

	if fi, err := os.Stat(dir); err != nil {
		return "cannot read " + dir + ": " + err.Error()
	} else if !fi.IsDir() {
		return dir + " exists but is not a directory"
	}
	// Can THIS process (the user) traverse the directory at all?
	if f, err := os.Open(dir); err != nil {
		return "no permission to open " + dir + " — it is probably owned by root. " +
			"Fix: sudo chown -R $(id -un) " + dir
	} else {
		f.Close()
	}
	st, err := os.Stat(sock)
	if err != nil {
		if os.IsNotExist(err) {
			return "no control socket at " + sock + " — the client is not running. Click Connect."
		}
		return "cannot stat " + sock + ": " + err.Error()
	}
	if st.Mode()&os.ModeSocket == 0 {
		return sock + " is not a socket (stale file). Remove it and Connect again."
	}
	// It exists and is a socket: try a bare connect to separate "nobody is
	// listening" (stale) from "not allowed" (ownership/permissions).
	c, err := net.DialTimeout("unix", sock, 3*time.Second)
	if err == nil {
		c.Close()
		return "the client is listening but did not answer in time — it may be busy or wedged; " +
			"Disconnect and Connect again."
	}
	if os.IsPermission(err) {
		return "permission denied on " + sock + " — the client is running as root and this app cannot " +
			"reach it. Fix: sudo chown -R $(id -un) " + dir + " then Disconnect and Connect."
	}
	return "stale control socket at " + sock + " (nothing is listening) — the client exited. Click Connect."
}

func fetchInfo() (map[string]any, bool) {
	cl := &http.Client{
		// 6s, not 2s. This result decides whether a client is ALREADY
		// RUNNING, and a false "no" is expensive: Connect then launches a
		// second client, which dies on the already-bound UDP port, so the
		// user sees a connect error while the original client keeps running
		// perfectly (their phone still lists this machine). /api/info walks
		// the interface list, so a busy or sleepy machine can exceed a 2s
		// budget — err on the side of waiting rather than double-launching.
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", controlSocket())
			},
		},
	}
	resp, err := cl.Get("http://unix/api/info")
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	var m map[string]any
	if json.NewDecoder(resp.Body).Decode(&m) != nil {
		return nil, false
	}
	return m, true
}

// doConnect / doDisconnect, notify, promptPassword, openBrowser and the
// clientExeName constant are platform-specific — see platform_darwin.go /
// platform_windows.go.

// --- settings ------------------------------------------------------------

// doSettings opens network Settings inside the gated admin panel, so first run
// forces creating an admin username/password before the settings form, and
// saving returns to the dashboard. (The standalone settings window in
// settings.go remains as a fallback but is no longer the primary entry.)
func doSettings() {
	if adminAddr == "" {
		openSettingsWindow()
		return
	}
	openBrowser("http://" + adminAddr + "/settings")
}

// networkHasAdminKey reports whether this device already knows a network admin
// key — either because it holds the signing key, has it pinned in config, or has
// received it via peer seeding (TOFU). Used to decide whether Settings offers to
// CREATE one.
func networkHasAdminKey() bool {
	if adminKeyAvailable() {
		return true
	}
	if strings.TrimSpace(loadConfig().AdminPublicKey) != "" {
		return true
	}
	if b, err := os.ReadFile(adminPubKeyPath()); err == nil && strings.TrimSpace(string(b)) != "" {
		return true
	}
	return false
}

// currentNetworkAdminPub returns the network admin public key this device knows,
// or "".
func currentNetworkAdminPub() string {
	if p := adminPublicKeyB64(); p != "" {
		return p
	}
	if p := strings.TrimSpace(loadConfig().AdminPublicKey); p != "" {
		return p
	}
	if b, err := os.ReadFile(adminPubKeyPath()); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}

func ensureFile(p string) {
	if _, err := os.Stat(p); err != nil {
		_ = os.WriteFile(p, []byte{}, 0o644)
	}
}

// --- config + paths ------------------------------------------------------

type mConfig struct {
	NetworkName    string `yaml:"network_name"`
	PSK            string `yaml:"psk"`
	FriendlyName   string `yaml:"friendly_name"`
	OverlayCIDR    string `yaml:"overlay_cidr"`
	NodePrivateKey string `yaml:"node_private_key"`
	UDPListenPort  int    `yaml:"udp_listen_port"`
	Cipher         string `yaml:"cipher"`
	PostQuantum    bool   `yaml:"post_quantum"`
	// IPv6 enables the dual-stack transport (on by default). Overlay stays IPv4.
	IPv6 bool `yaml:"ipv6"`
	// PortPrediction forces symmetric-NAT port prediction on. The client also
	// turns it on by itself once it classifies the NAT as symmetric, so this is
	// an override rather than a switch. It was previously absent from this
	// struct entirely, which meant the key never appeared in the generated
	// client.yaml and the desktop build could not enable it at all — on a
	// router with symmetric NAT that left every NATed peer permanently RELAYED
	// with no way to change it short of hand-editing the file.
	PortPrediction bool `yaml:"port_prediction"`
	// ExitNode offers THIS device as an internet exit for the mesh: it NATs
	// overlay-sourced traffic out its physical interface so full-VPN peers can
	// egress here. Implemented on Linux (iptables) and macOS (pf); the client
	// auto-disables it with a log line on platforms that can't forward.
	ExitNode bool `yaml:"exit_node"`
	// UseExit routes ALL of this device's internet traffic through an exit
	// node on the mesh (full VPN). ExitPeer picks WHICH exit: blank = the
	// fastest reachable exit (auto-switching); or pin one node by its overlay
	// IP, friendly name, base64 public key, or key-fingerprint prefix.
	UseExit  bool   `yaml:"use_exit"`
	ExitPeer string `yaml:"exit_peer"`
	Tun      struct {
		MTU         int    `yaml:"mtu"`
		AddressCIDR string `yaml:"address_cidr"`
	} `yaml:"tun"`
	STUNServers []string `yaml:"stun_servers"`
	// RendezvousServers are optional HTTP(S) discovery servers, used on networks
	// that block BitTorrent (see rendezvous/).
	RendezvousServers []string `yaml:"rendezvous_servers"`
	// RendezvousAuth is the credential for servers that require one. ONE
	// field, two schemes, auto-detected by the client: "user:password" sends
	// HTTP Basic; anything without a colon is sent as a Bearer token.
	RendezvousAuth string `yaml:"rendezvous_auth"`
	// AdminPublicKey is ignored by the client (which reads ADMIN_PUBLIC_KEY
	// from the environment); the menu-bar app stores it here and passes it in
	// at Connect so network revocations apply to this Mac.
	AdminPublicKey string `yaml:"admin_public_key"`
}

// applyDefaults fills in everything the client needs beyond the user-entered
// network name / PSK — including STUN servers, without which internet
// (non-LAN) peers can't hole-punch.
func applyDefaults(c *mConfig) {
	c.NodePrivateKey = nodeKeyPath()
	if c.Cipher == "" {
		c.Cipher = "aesgcm"
	}
	if c.Tun.MTU == 0 {
		c.Tun.MTU = 1280
	}
	if c.OverlayCIDR == "" {
		c.OverlayCIDR = "10.22.55.0/24"
	}
	if c.UDPListenPort == 0 {
		c.UDPListenPort = 6969
	}
	if len(c.STUNServers) == 0 {
		c.STUNServers = []string{
			"stun:stun.l.google.com:19302",
			"stun:stun1.l.google.com:19302",
			"stun:global.stun.twilio.com:3478",
		}
	}
}

// overlayAddrFromInput turns a user's overlay-IP entry into a pinned address
// for tun.address_cidr. Blank = auto-derive from the node key. A bare number
// (e.g. "29") becomes the last octet of the overlay subnet. A dotted value is
// used as-is (bare IP or CIDR).
func overlayAddrFromInput(input, cidr string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	if strings.Contains(input, ".") {
		return input
	}
	base := cidr
	if base == "" {
		base = "10.22.55.0/24"
	}
	if i := strings.IndexByte(base, '/'); i >= 0 {
		base = base[:i]
	}
	octs := strings.Split(base, ".")
	if len(octs) != 4 {
		return ""
	}
	return octs[0] + "." + octs[1] + "." + octs[2] + "." + input
}

func loadConfig() mConfig {
	// Post-quantum is ON by default; an absent post_quantum key stays true (yaml
	// only overwrites keys present in the file). Set it false to disable.
	c := mConfig{PostQuantum: true, IPv6: true, PortPrediction: true}
	if data, err := os.ReadFile(configPath()); err == nil {
		_ = yaml.Unmarshal(data, &c)
	}
	return c
}

// blankConfig is a fresh, unconfigured network with the same safe defaults as a
// first run. Used to seed the Settings form when adding a new network.
func blankConfig() mConfig { return mConfig{PostQuantum: true, IPv6: true, PortPrediction: true} }

func saveConfig(c mConfig) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(), data, 0o600)
}

func appDir() string {
	h, _ := os.UserHomeDir()
	d := filepath.Join(h, ".apgo")
	_ = os.MkdirAll(d, 0o700)
	return d
}

func configPath() string      { return filepath.Join(appDir(), "client.yaml") }
func controlSocket() string   { return filepath.Join(appDir(), "control.sock") }
func provisionsPath() string  { return filepath.Join(appDir(), "provisions.json") }
func revocationsPath() string { return filepath.Join(appDir(), "revocations.json") }
func sealedKeyPath() string   { return filepath.Join(appDir(), "admin-key-sealed.json") }
func approvalsPath() string   { return filepath.Join(appDir(), "approvals.json") }
func netConfigPath() string   { return filepath.Join(appDir(), "netconfig.json") }
func trackersPath() string    { return filepath.Join(appDir(), "trackers.txt") }
func policyPath() string      { return filepath.Join(appDir(), "policy.json") }
func netSharesPath() string { return filepath.Join(appDir(), "netshares.json") }

// networksStateDir holds secondary-network profiles + per-network child state
// (see client/multinet.go). NOT the tray's profile-switcher dir ("networks").
func networksStateDir() string { return filepath.Join(appDir(), "netstate") }
func logPath() string       { return filepath.Join(appDir(), "overlay-client.log") }

// lastClientError digs the actual reason out of the tail of the client log so
// a failed Connect can SAY what went wrong instead of pointing at a file.
// Recognises the handful of causes that account for nearly every failure;
// falls back to the last non-empty log line, which is almost always the fatal
// one, and finally to a plain instruction.
func lastClientError() string {
	data, err := os.ReadFile(logPath())
	if err != nil {
		return "no log yet at " + logPath() + " (the client may not have started at all — check privileges)."
	}
	// Only look at the tail; the log accumulates across runs.
	if len(data) > 64<<10 {
		data = data[len(data)-(64<<10):]
	}
	lines := strings.Split(string(data), "\n")
	var lastNonEmpty string
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l == "" {
			continue
		}
		if lastNonEmpty == "" {
			lastNonEmpty = l
		}
		switch {
		case strings.Contains(l, "address already in use"):
			return "UDP port already in use — another APGO client is still running. " +
				"Use Disconnect first, or reboot if it persists."
		case strings.Contains(l, "create TUN"), strings.Contains(l, "operation not permitted"):
			return "could not create the network interface (needs administrator rights). " +
				"Approve the password prompt, or reinstall to restore the helper."
		case strings.Contains(l, "node not configured"):
			return "the client is waiting for a network name and PSK — open Settings and save them."
		case strings.Contains(l, "psk"), strings.Contains(l, "PSK"):
			if strings.Contains(strings.ToLower(l), "invalid") || strings.Contains(strings.ToLower(l), "parse") {
				return "the pre-shared key is not valid — re-enter it in Settings (it must start with base64:)."
			}
		}
	}
	if lastNonEmpty != "" {
		return "last log line: " + lastNonEmpty
	}
	return "the log is empty; open it from the menu for details."
}
func pidPath() string        { return filepath.Join(appDir(), "client.pid") }
func nodeKeyPath() string    { return filepath.Join(appDir(), "node.key") }
func adminPubKeyPath() string { return filepath.Join(appDir(), "admin-pubkey") }

// clientBinary locates the overlay-client: $OVERLAY_CLIENT_BIN, then next to
// this executable (inside the .app bundle), then $PATH.
func clientBinary() string {
	if b := os.Getenv("OVERLAY_CLIENT_BIN"); b != "" {
		return b
	}
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), clientExeName)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return clientExeName
}
