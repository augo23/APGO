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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	mQuit       *systray.MenuItem
)

func main() { systray.Run(onReady, func() {}) }

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
	setupNetworksMenu() // "Networks" submenu: switch / save / delete profiles
	mLogin = systray.AddMenuItemCheckbox("Start at login", "Launch APGO and connect when you log in", loginStartEnabled())
	systray.AddSeparator()
	mQuit = systray.AddMenuItem("Quit", "")

	startAdminServer()

	// If start-at-login is on and we have a usable config, connect automatically
	// once the tray is up (this run was almost certainly triggered by login).
	if loginStartEnabled() {
		if c := loadConfig(); c.NetworkName != "" && c.PSK != "" {
			go func() {
				time.Sleep(1500 * time.Millisecond)
				if _, ok := fetchInfo(); !ok { // not already running
					doConnect()
				}
			}()
		}
	}

	go loop()
}

func loop() {
	poll := time.NewTicker(2 * time.Second)
	defer poll.Stop()
	refreshStatus()
	for {
		select {
		case <-mConnect.ClickedCh:
			go doConnect()
		case <-mDisconnect.ClickedCh:
			go doDisconnect()
		case <-mSettings.ClickedCh:
			go doSettings()
		case <-mAdmin.ClickedCh:
			openAdminPanel()
		case <-mLogin.ClickedCh:
			toggleLoginStart()
		case <-mQuit.ClickedCh:
			systray.Quit()
			return
		case <-poll.C:
			refreshStatus()
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

// --- status --------------------------------------------------------------

func refreshStatus() {
	info, ok := fetchInfo()
	if ok {
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
		mStatus.SetTitle("○ Disconnected")
		mPeers.SetTitle("Peers: —")
		mConnect.Enable()
		mDisconnect.Disable()
	}
}

func fetchInfo() (map[string]any, bool) {
	cl := &http.Client{
		Timeout: 2 * time.Second,
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
		c.OverlayCIDR = "10.28.55.0/24"
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
		base = "10.28.55.0/24"
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
	c := mConfig{PostQuantum: true, IPv6: true}
	if data, err := os.ReadFile(configPath()); err == nil {
		_ = yaml.Unmarshal(data, &c)
	}
	return c
}

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
func logPath() string       { return filepath.Join(appDir(), "overlay-client.log") }
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
