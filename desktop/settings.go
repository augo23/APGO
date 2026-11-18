package main

// settings.go presents all settings in ONE window. macOS's native dialog can't
// hold multiple text fields, so we serve a tiny form from a localhost-only,
// single-use HTTP endpoint and open it in the browser. The PSK is a password
// field (with a show toggle). The server shuts down after Save or a timeout.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

func randToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// openSettingsWindow edits the CURRENT network.
func openSettingsWindow() { serveSettingsForm(loadConfig()) }

// openNewNetworkWindow starts a blank form for adding a new network. The POST
// path is identical — saving writes the entered values as the active config and
// registers them as a new switchable profile.
func openNewNetworkWindow() { serveSettingsForm(blankConfig()) }

func serveSettingsForm(initial mConfig) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		notify("Could not open Settings: " + err.Error())
		return
	}
	token := randToken()
	var once sync.Once
	done := make(chan struct{})
	finish := func() { once.Do(func() { close(done) }) }

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("t") != token {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			note, err := saveSettingsForm(r)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "<p>Save failed: %s</p>", html.EscapeString(err.Error()))
				return
			}
			fmt.Fprint(w, savedPage)
			if note != "" {
				notify(note)
			} else {
				notify("Settings saved. Click Connect to join.")
			}
			go func() { time.Sleep(400 * time.Millisecond); finish() }()
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, settingsPage(initial))
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: time.Minute, IdleTimeout: 2 * time.Minute}
	go func() { _ = srv.Serve(ln) }()

	url := fmt.Sprintf("http://%s/?t=%s", ln.Addr().String(), token)
	openBrowser(url)

	go func() {
		select {
		case <-done:
		case <-time.After(5 * time.Minute):
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
}

// saveSettingsForm reads the settings form and persists the config. Shared by
// the standalone Settings window and the "/settings" route in the admin panel.
//
// It returns a note for the user about the exit-node and public-exit
// settings, which (unlike the others) are applied to the running client
// immediately. Full VPN itself is set from the dashboard's main page.
func saveSettingsForm(r *http.Request) (string, error) {
	_ = r.ParseForm()
	c := loadConfig()
	prevNet := c.NetworkName
	prevExitNode := c.ExitNode
	prevPublicExit := c.PublicExit
	prevPXLimits := [5]string{c.PublicExitUpLimit, c.PublicExitDownLimit, c.PublicExitQuota,
		strconv.Itoa(c.PublicExitMaxClients), c.PublicExitPerClientLimit}
	c.NetworkName = strings.TrimSpace(r.FormValue("network_name"))
	if c.NetworkName != prevNet {
		// A different network (including "+ Add Network", which starts from
		// a blank form): the previous network's Full VPN choice and pinned
		// exit mean nothing there. This form used to send use_exit unticked
		// and so reset it implicitly; the Full VPN panel now owns it.
		c.UseExit, c.ExitPeer = false, ""
	}
	c.PSK = strings.TrimSpace(r.FormValue("psk"))
	c.FriendlyName = strings.TrimSpace(r.FormValue("friendly_name"))
	// Post-quantum is controlled network-wide from the Security policy page
	// (one place), not here — leave c.PostQuantum as loaded (default on).
	c.IPv6 = r.FormValue("ipv6") == "on"
	c.ExitNode = r.FormValue("exit_node") == "on"
	// Full VPN (use_exit, exit_peer, use_public_exits) is set from the Full
	// VPN panel on the dashboard's main page (fullvpn.go), not this form, so
	// the saved values are kept as loaded.
	c.PublicExit = r.FormValue("public_exit") == "on"
	c.PublicExitUpLimit = strings.TrimSpace(r.FormValue("public_exit_up"))
	c.PublicExitDownLimit = strings.TrimSpace(r.FormValue("public_exit_down"))
	c.PublicExitQuota = strings.TrimSpace(r.FormValue("public_exit_quota"))
	c.PublicExitPerClientLimit = strings.TrimSpace(r.FormValue("public_exit_per_client"))
	c.PublicExitMaxClients = 0
	if v := strings.TrimSpace(r.FormValue("public_exit_max_clients")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1024 {
			return "", fmt.Errorf("public exit node: max clients must be a number from 1 to 1024")
		}
		c.PublicExitMaxClients = n
	}
	// Discovery + relay switches. Written as explicit true/false (not left nil)
	// because they are presented here as checkboxes: an unticked box is a
	// decision, and treating it as "unset" would let a stale node-config record
	// silently turn the feature back on.
	dht := r.FormValue("dht") == "on"
	useRelays := r.FormValue("use_public_relays") == "on"
	c.DHT = &dht
	c.UseRelays = &useRelays
	c.PublicRelay = r.FormValue("public_relay") == "on"
	if c.PublicExit && (!dht || !c.PublicRelay) {
		return "", fmt.Errorf("a public exit node must also find peers through the DHT and be a public relay — tick both, or untick Public exit node")
	}
	c.OverlayCIDR = strings.TrimSpace(r.FormValue("overlay_cidr"))
	if c.OverlayCIDR == "" {
		c.OverlayCIDR = "10.22.55.0/24"
	}
	// Blank (or invalid) means AUTOMATIC: 0 tells the client to derive a
	// stable, per-device port instead of contending for a shared default with
	// every other node behind this router.
	if p, err := strconv.Atoi(strings.TrimSpace(r.FormValue("port"))); err == nil && p > 0 {
		c.UDPListenPort = p
	} else {
		c.UDPListenPort = 0
	}
	c.Tun.AddressCIDR = overlayAddrFromInput(r.FormValue("last_octet"), c.OverlayCIDR)
	// Recombine the two credential boxes into the single string the client
	// takes: "user:pass" = Basic, bare = Bearer, "" = no credential.
	if u := strings.TrimSpace(r.FormValue("rendezvous_user")); u == "" {
		c.RendezvousAuth = ""
	} else if p := strings.TrimSpace(r.FormValue("rendezvous_pass")); p == "" {
		c.RendezvousAuth = u
	} else {
		c.RendezvousAuth = u + ":" + p
	}
	c.RendezvousServers = nil
	for _, s := range strings.Split(r.FormValue("rendezvous"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			c.RendezvousServers = append(c.RendezvousServers, s)
		}
	}

	// Admin key: create one if no usable signing key is present and a password
	// was given; otherwise, if a new admin password was supplied, change it.
	// Both paths require typing the password twice (verified).
	if !adminKeyAvailable() {
		if pw := strings.TrimSpace(r.FormValue("admin_key_password")); pw != "" {
			if pw != strings.TrimSpace(r.FormValue("admin_key_password_confirm")) {
				return "", fmt.Errorf("the network admin passwords don't match — type the same one in both boxes")
			}
			pub, err := genAdminKey(pw)
			if err != nil {
				return "", err
			}
			c.AdminPublicKey = pub
			notify("Admin key created — distributing it to your devices.")
		}
	} else if np := r.FormValue("admin_new_password"); np != "" {
		if np != r.FormValue("admin_new_password_confirm") {
			return "", fmt.Errorf("the new network admin passwords don't match — type the same one in both boxes")
		}
		if err := changeAdminPassword(r.FormValue("admin_current_password"), np); err != nil {
			return "", err
		}
		notify("Network admin password changed — redistributing the key.")
	}

	// Dashboard login change (inline on this page; was the separate /account
	// window). Only when a new password was entered; typed twice + current
	// password verified, so a typo can't lock the user out.
	if np := r.FormValue("dash_new_password"); np != "" {
		if np != r.FormValue("dash_new_password_confirm") {
			return "", fmt.Errorf("the new dashboard passwords don't match — type the same one in both boxes")
		}
		u := strings.TrimSpace(r.FormValue("dash_username"))
		if u == "" || len(np) < 6 {
			return "", fmt.Errorf("dashboard username is required and the new password must be at least 6 characters")
		}
		if !verifyCurrentPassword(r.FormValue("dash_current_password")) {
			return "", fmt.Errorf("current dashboard password is incorrect")
		}
		nc, err := newCreds(u, np)
		if err == nil {
			err = saveCreds(nc)
		}
		if err != nil {
			return "", err
		}
		notify("Dashboard login updated.")
	}

	applyDefaults(&c)
	if err := saveConfig(c); err != nil {
		return "", err
	}
	// Every settings save with a network name registers/updates that network's
	// switchable profile — this is how new networks are added: just enter the
	// new name + PSK and Save, then switch between them in the tray's
	// "Networks" submenu.
	registerCurrentProfileUI()
	// Exit-node and public-exit modes apply live — but only to the network the
	// client is running, and only when the running client isn't already
	// doing what was saved.
	if c.NetworkName != prevNet {
		return "", nil
	}
	var notes []string
	if exitNodeDiffers(c.ExitNode, prevExitNode) {
		if n := applyExitNodeLive(c.ExitNode); n != "" {
			notes = append(notes, n)
		}
	}
	pxLimits := [5]string{c.PublicExitUpLimit, c.PublicExitDownLimit, c.PublicExitQuota,
		strconv.Itoa(c.PublicExitMaxClients), c.PublicExitPerClientLimit}
	if c.PublicExit != prevPublicExit || pxLimits != prevPXLimits || publicExitDiffers(c.PublicExit) {
		if n := applyPublicExitLive(c); n != "" {
			notes = append(notes, n)
		}
	}
	if c.UseExit && (c.ExitNode || c.PublicExit) {
		notes = append(notes, "Note: while Full VPN is on, this computer's own traffic goes through another exit, "+
			"so it can't reliably be an exit for other devices — turn Full VPN off on this computer to share its connection.")
	}
	return strings.Join(notes, " "), nil
}

func settingsPage(c mConfig) string {
	port := "" // blank = automatic
	if c.UDPListenPort > 0 {
		port = strconv.Itoa(c.UDPListenPort)
	}
	cidr := c.OverlayCIDR
	if cidr == "" {
		cidr = "10.22.55.0/24"
	}
	lastOctet := ""
	if a := c.Tun.AddressCIDR; a != "" {
		ipp := a
		if i := strings.IndexByte(ipp, '/'); i >= 0 {
			ipp = ipp[:i]
		}
		if octs := strings.Split(ipp, "."); len(octs) == 4 {
			lastOctet = octs[3]
		}
	}
	ipv6Checked := ""
	if c.IPv6 {
		ipv6Checked = "checked"
	}
	exitNodeChecked := ""
	if c.ExitNode {
		exitNodeChecked = "checked"
	}
	maxClients := ""
	if c.PublicExitMaxClients > 0 {
		maxClients = strconv.Itoa(c.PublicExitMaxClients)
	}
	// All three default to OFF in the client when the key is absent, so an
	// unset pointer must render unticked — showing them ticked would claim a
	// node is on the DHT when it is not.
	checkedIf := func(b bool) string {
		if b {
			return "checked"
		}
		return ""
	}
	setBool := func(p *bool) bool { return p != nil && *p }
	dhtChecked := checkedIf(setBool(c.DHT))
	useRelaysChecked := checkedIf(setBool(c.UseRelays))
	publicRelayChecked := checkedIf(c.PublicRelay)
	// Split the stored rendezvous credential back into its two boxes.
	rvUser, rvPass := c.RendezvousAuth, ""
	if u, p, ok := strings.Cut(c.RendezvousAuth, ":"); ok {
		rvUser, rvPass = u, p
	}
	return strings.NewReplacer(
		"{{NETWORK}}", html.EscapeString(c.NetworkName),
		"{{PSK}}", html.EscapeString(c.PSK),
		"{{FRIENDLY}}", html.EscapeString(c.FriendlyName),
		"{{IPV6CHECK}}", ipv6Checked,
		"{{EXITNODECHECK}}", exitNodeChecked,
		"{{PUBLICEXITCHECK}}", checkedIf(c.PublicExit),
		"{{PXUP}}", html.EscapeString(c.PublicExitUpLimit),
		"{{PXDOWN}}", html.EscapeString(c.PublicExitDownLimit),
		"{{PXQUOTA}}", html.EscapeString(c.PublicExitQuota),
		"{{PXMAX}}", html.EscapeString(maxClients),
		"{{PXPER}}", html.EscapeString(c.PublicExitPerClientLimit),
		"{{DHTCHECK}}", dhtChecked,
		"{{USERELAYSCHECK}}", useRelaysChecked,
		"{{PUBLICRELAYCHECK}}", publicRelayChecked,
		"{{CIDR}}", html.EscapeString(cidr),
		"{{PORT}}", html.EscapeString(port),
		"{{LASTOCTET}}", html.EscapeString(lastOctet),
		"{{RENDEZVOUS}}", html.EscapeString(strings.Join(c.RendezvousServers, ", ")),
		"{{RVUSER}}", html.EscapeString(rvUser),
		"{{RVPASS}}", html.EscapeString(rvPass),
		"{{ADMINSECTION}}", adminSectionHTML(),
		"{{DASHSECTION}}", dashboardSectionHTML(),
	).Replace(settingsTmpl)
}

// adminSectionHTML renders the admin-key part of the settings form: a create
// field when the network has no admin key yet, or the read-only current key
// (to copy onto other nodes) when one exists.
func adminSectionHTML() string {
	if adminKeyAvailable() {
		pub := currentNetworkAdminPub()
		body := `<div class="hint">This network has an admin key. It's distributed (encrypted) to every device, so you can manage nodes from any device with the network admin password.</div>`
		if pub != "" {
			body += `
    <textarea readonly onclick="this.select()" style="width:100%;height:64px;margin-top:8px;background:var(--field);color:var(--fg);border:1px solid var(--line);border-radius:10px;padding:10px;font-family:ui-monospace,Menlo,monospace;font-size:12px">ADMIN_PUBLIC_KEY=` + html.EscapeString(pub) + `</textarea>`
		}
		body += `
    <label for="admin_current_password">Change network admin password — current</label>
    <input id="admin_current_password" name="admin_current_password" type="password" autocomplete="off">
    <label for="admin_new_password">Change network admin password — new (min 8)</label>
    <input id="admin_new_password" name="admin_new_password" type="password" autocomplete="off">
    <label for="admin_new_password_confirm">Confirm new network admin password</label>
    <input id="admin_new_password_confirm" name="admin_new_password_confirm" type="password" autocomplete="off">
    <div class="hint">Re-encrypts the admin key under the new password and re-distributes it to every device. Leave blank to keep the current password.</div>`
		return body
	}
	return `<label for="admin_key_password">Create network admin key — set the network admin password (optional)</label>
    <input id="admin_key_password" name="admin_key_password" type="password" spellcheck="false" autocapitalize="off">
    <label for="admin_key_password_confirm">Confirm the network admin password</label>
    <input id="admin_key_password_confirm" name="admin_key_password_confirm" type="password" spellcheck="false" autocapitalize="off">
    <div class="hint">No network admin key exists yet. Enter a <b>network admin password</b> (min 8 chars) to create one now — it's seeded (encrypted) to all your devices automatically and unlocks network-wide revocation, approvals, and node changes. This is separate from your dashboard login password. Leave blank to skip.</div>`
}

// dashboardSectionHTML renders the dashboard-login (account) change fields
// inline on the Settings page — previously a separate /account page/window.
// Only shown once a dashboard login exists (first run creates it via the
// admin-panel gate before Settings is reachable).
func dashboardSectionHTML() string {
	u := currentUsername()
	if u == "" {
		return ""
	}
	return `<h2>Dashboard login</h2>
    <div class="hint">Change the username/password used to open THIS device's dashboard (separate from the network admin password). Leave blank to keep the current login.</div>
    <label for="dash_current_password">Current dashboard password</label>
    <input id="dash_current_password" name="dash_current_password" type="password" autocomplete="off">
    <label for="dash_username">Dashboard username</label>
    <input id="dash_username" name="dash_username" type="text" value="` + html.EscapeString(u) + `" spellcheck="false" autocapitalize="off">
    <label for="dash_new_password">New dashboard password (min 6)</label>
    <input id="dash_new_password" name="dash_new_password" type="password" autocomplete="off">
    <label for="dash_new_password_confirm">Confirm new dashboard password</label>
    <input id="dash_new_password_confirm" name="dash_new_password_confirm" type="password" autocomplete="off">`
}

const settingsTmpl = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>APGO Settings</title>
<style>
  :root{ --bg:#000; --panel:#0c0c0c; --fg:#fff; --muted:#9aa0a6; --line:#242424; --accent:#fff; --field:#111; }
  @media (prefers-color-scheme: light){
    :root{ --bg:#fff; --panel:#f6f6f6; --fg:#0a0a0a; --muted:#5f6368; --line:#e2e2e2; --accent:#000; --field:#fff; }
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;display:flex;justify-content:center;padding:28px 16px}
  form{width:100%;max-width:640px;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:0 26px 26px}
  .top{position:sticky;top:0;background:var(--panel);padding:22px 0 0;z-index:2;border-bottom:1px solid var(--line);margin-bottom:6px}
  .titlerow{display:flex;align-items:center;gap:12px;margin-bottom:14px}
  h1{font-size:18px;margin:0;flex:1}
  .tabs{display:flex;gap:2px;overflow-x:auto;scrollbar-width:none}
  .tabs::-webkit-scrollbar{display:none}
  .tab{flex:none;background:none;border:0;border-bottom:2px solid transparent;color:var(--muted);font:inherit;font-size:14px;font-weight:600;padding:9px 12px;cursor:pointer;white-space:nowrap}
  .tab:hover{color:var(--fg)}
  .tab[aria-selected=true]{color:var(--fg);border-bottom-color:var(--accent)}
  .tab:focus-visible{outline:2px solid var(--accent);outline-offset:-2px;border-radius:6px}
  section[role=tabpanel]{padding-top:6px}
  p.sub{margin:14px 0 4px;color:var(--muted);font-size:13px}
  h2{font-size:13px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin:26px 0 0;padding-top:16px;border-top:1px solid var(--line)}
  h2.first{border-top:0;padding-top:0;margin-top:18px}
  label{display:block;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin:16px 0 6px}
  label.check{display:flex;align-items:flex-start;gap:10px;margin-top:16px;text-transform:none;letter-spacing:0;font-size:15px;color:var(--fg);cursor:pointer}
  label.check input{width:auto;margin-top:4px;flex:none}
  input,textarea{width:100%;padding:11px 12px;background:var(--field);color:var(--fg);border:1px solid var(--line);border-radius:10px;font-size:15px;outline:none}
  input:focus{border-color:var(--accent)}
  .pskrow{position:relative}
  .toggle{position:absolute;right:10px;top:9px;font-size:12px;color:var(--muted);background:none;border:0;cursor:pointer}
  .genbtn{margin-top:8px;padding:9px 14px;font-size:13px;font-weight:600;color:var(--fg);background:var(--field);border:1px solid var(--line);border-radius:10px;cursor:pointer}
  .genbtn:hover{border-color:var(--accent)}
  .hint{color:var(--muted);font-size:12px;margin-top:6px}
  label.check + .hint{margin-left:24px}
  .grid2{display:flex;gap:8px;flex-wrap:wrap}
  .grid2 > div{flex:1;min-width:130px}
  .callout{border:1px solid var(--line);border-radius:10px;padding:10px 12px;font-size:13px;color:var(--muted);margin-top:16px}
  .callout a{color:var(--fg)}
  .links a{display:block;color:var(--fg);margin-top:8px;font-size:14px}
  button.save{width:100%;margin-top:26px;padding:12px;border:0;border-radius:10px;background:var(--accent);color:var(--bg);font-size:15px;font-weight:600;cursor:pointer}
  .savenote{color:var(--muted);font-size:12px;text-align:center;margin-top:8px}
  a.backtop{color:var(--fg);font-size:13px;font-weight:600;text-decoration:none;border:1px solid var(--line);padding:7px 14px;border-radius:10px}
</style></head>
<body>
  <form method="POST" autocomplete="off" id="settingsForm">
    <div class="top">
      <div class="titlerow">
        <h1>Settings</h1>
        <a class="backtop" href="/">← Dashboard</a>
      </div>
      <div class="tabs" role="tablist" aria-label="Settings sections">
        <button type="button" class="tab" role="tab" id="tab-device" aria-controls="pane-device" aria-selected="true">This device</button>
        <button type="button" class="tab" role="tab" id="tab-network" aria-controls="pane-network" aria-selected="false" tabindex="-1">Network</button>
        <button type="button" class="tab" role="tab" id="tab-discovery" aria-controls="pane-discovery" aria-selected="false" tabindex="-1">Discovery &amp; relays</button>
        <button type="button" class="tab" role="tab" id="tab-sharing" aria-controls="pane-sharing" aria-selected="false" tabindex="-1">Sharing</button>
        <button type="button" class="tab" role="tab" id="tab-admin" aria-controls="pane-admin" aria-selected="false" tabindex="-1">Admin &amp; login</button>
      </div>
    </div>

    <!-- ===== This device ===== -->
    <section role="tabpanel" id="pane-device" aria-labelledby="tab-device">
      <p class="sub">Settings for this computer only.</p>

      <label for="friendly_name">Device name</label>
      <input id="friendly_name" name="friendly_name" type="text" value="{{FRIENDLY}}" spellcheck="false" autocapitalize="off" placeholder="e.g. austin-macbook">
      <div class="hint">Shown next to this device in every dashboard.</div>

      <label for="last_octet">Overlay IP</label>
      <div style="display:flex;align-items:center;gap:8px">
        <span id="ipprefix" style="color:var(--muted);font-family:ui-monospace,Menlo,monospace;white-space:nowrap">10.22.55.</span>
        <input id="last_octet" name="last_octet" type="text" inputmode="numeric" maxlength="3" value="{{LASTOCTET}}" style="max-width:96px" spellcheck="false" placeholder="auto">
      </div>
      <div class="hint">Just the last number (1–254). Blank = assigned automatically (recommended). To make an address permanent, assign it to this device in the dashboard's node settings.</div>

      <label for="port">UDP listen port</label>
      <input id="port" name="port" type="number" value="{{PORT}}" min="1" max="65535" placeholder="automatic">
      <div class="hint">Blank = automatic. An automatic port is stable and unique to this device, so several devices behind one router never compete for the same port.</div>

      <label class="check"><input type="checkbox" name="ipv6" {{IPV6CHECK}}> IPv6 transport</label>
      <div class="hint">Connect directly over IPv6 where this computer has a public IPv6 address — no NAT in the way. The overlay itself stays IPv4. Applies on reconnect.</div>

      <div class="callout">Full VPN and the choice of exit node are on the <a href="/">dashboard's main page</a>.</div>
    </section>

    <!-- ===== Network ===== -->
    <section role="tabpanel" id="pane-network" aria-labelledby="tab-network" hidden>
      <p class="sub">These must be the same on every device in the network.</p>

      <label for="network_name">Network name</label>
      <input id="network_name" name="network_name" type="text" value="{{NETWORK}}" spellcheck="false" autocapitalize="off">

      <label for="psk">Pre-shared key</label>
      <div class="pskrow">
        <input id="psk" name="psk" type="password" value="{{PSK}}" spellcheck="false" autocapitalize="off">
        <button type="button" class="toggle" onclick="var p=document.getElementById('psk');p.type=p.type==='password'?'text':'password';this.textContent=p.type==='password'?'Show':'Hide'">Show</button>
      </div>
      <button type="button" class="genbtn" onclick="var b=new Uint8Array(32);crypto.getRandomValues(b);document.getElementById('psk').value='base64:'+btoa(String.fromCharCode.apply(null,b))">Generate a random key</button>
      <div class="hint">Generate one, or paste the key your other devices use.</div>

      <label for="overlay_cidr">Overlay subnet</label>
      <input id="overlay_cidr" name="overlay_cidr" type="text" value="{{CIDR}}" spellcheck="false" placeholder="10.22.55.0/24">

      <h2>Rendezvous servers</h2>
      <label for="rendezvous">Server URLs (optional)</label>
      <input id="rendezvous" name="rendezvous" type="text" value="{{RENDEZVOUS}}" spellcheck="false" autocapitalize="off" placeholder="https://rv.example.com">
      <div class="hint">For networks that block BitTorrent trackers. Comma-separated. Blank = trackers only.</div>
      <div class="grid2">
        <div><label for="rendezvous_user">Username or token</label>
          <input id="rendezvous_user" name="rendezvous_user" type="text" value="{{RVUSER}}" spellcheck="false" autocapitalize="off" placeholder="blank if open"></div>
        <div><label for="rendezvous_pass">Password</label>
          <input id="rendezvous_pass" name="rendezvous_pass" type="password" value="{{RVPASS}}" placeholder="blank if using a token"></div>
      </div>
      <div class="hint">Username <b>and</b> password for HTTP Basic, or just a token in the first box. Included in the Join QR code, so phones that scan it need no typing.</div>

      <h2>Network-wide policy</h2>
      <div class="links">
        <a href="/network">Security policy &amp; identity rotation →</a>
        <a href="/trackers">Tracker list →</a>
      </div>
      <div class="hint">Settings for other devices (relay, exit, IPv6, name and address) are in each node's <b>Settings…</b> sheet on the dashboard.</div>
    </section>

    <!-- ===== Discovery & relays ===== -->
    <section role="tabpanel" id="pane-discovery" aria-labelledby="tab-discovery" hidden>
      <p class="sub">How this device finds your other devices, and what it does when a direct connection fails.</p>

      <label class="check"><input type="checkbox" name="dht" {{DHTCHECK}}> Find peers through the BitTorrent DHT</label>
      <div class="hint">A second way to find your devices when trackers are blocked or down. The DHT only carries addresses; joining still needs your pre-shared key. Applies on reconnect.</div>

      <label class="check"><input type="checkbox" name="use_public_relays" {{USERELAYSCHECK}}> Use public relays when a direct path fails</label>
      <div class="hint">Last resort when two devices can't connect through their routers: they meet through a volunteer relay, which only forwards encrypted data it cannot read. Applies on reconnect.</div>
    </section>

    <!-- ===== Sharing ===== -->
    <section role="tabpanel" id="pane-sharing" aria-labelledby="tab-sharing" hidden>
      <p class="sub">What this device offers to others. Each uses this computer's bandwidth.</p>

      <label class="check"><input type="checkbox" name="exit_node" {{EXITNODECHECK}}> Internal exit node</label>
      <div class="hint">Lets devices on <b>your</b> network send their internet traffic out through this computer (they see it with a green <b style="color:#3fb950">E</b>). Applies immediately.</div>

      <label class="check"><input type="checkbox" name="public_relay" {{PUBLICRELAYCHECK}}> Be a public relay</label>
      <div class="hint">Forwards encrypted traffic for <b>anyone's</b> devices that can't connect directly. It can read nothing. Best on a machine with a good connection that stays online. Applies on reconnect.</div>

      <label class="check"><input type="checkbox" id="public_exit" name="public_exit" {{PUBLICEXITCHECK}}> Public exit node</label>
      <div class="hint" id="public_exit_hint">Lets <b>any</b> APGO user send internet traffic out through this computer. They reach the internet only — never your network, your LAN or this computer — and outbound mail is blocked. <b>Their traffic leaves from your IP address.</b> Needs <i>Find peers through the BitTorrent DHT</i> (Discovery tab) and <i>Be a public relay</i>.</div>
      <div id="public_exit_limits" style="margin-left:24px">
        <div class="grid2">
          <div><label for="public_exit_up">Upload limit</label><input id="public_exit_up" name="public_exit_up" type="text" value="{{PXUP}}" placeholder="e.g. 20mbit" spellcheck="false"></div>
          <div><label for="public_exit_down">Download limit</label><input id="public_exit_down" name="public_exit_down" type="text" value="{{PXDOWN}}" placeholder="e.g. 50mbit" spellcheck="false"></div>
        </div>
        <div class="grid2">
          <div><label for="public_exit_quota">Monthly quota</label><input id="public_exit_quota" name="public_exit_quota" type="text" value="{{PXQUOTA}}" placeholder="e.g. 200GB" spellcheck="false"></div>
          <div><label for="public_exit_max_clients">Max people at once</label><input id="public_exit_max_clients" name="public_exit_max_clients" type="number" min="1" max="1024" value="{{PXMAX}}" placeholder="16"></div>
          <div><label for="public_exit_per_client">Per person</label><input id="public_exit_per_client" name="public_exit_per_client" type="text" value="{{PXPER}}" placeholder="10mbit" spellcheck="false"></div>
        </div>
        <div class="hint">Blank = unlimited (per person defaults to 10 Mbit/s). Separate from the relay and internal exit budgets.</div>
      </div>
    </section>

    <!-- ===== Admin & login ===== -->
    <section role="tabpanel" id="pane-admin" aria-labelledby="tab-admin" hidden>
      <h2 class="first">Network admin key</h2>
      {{ADMINSECTION}}

      {{DASHSECTION}}
    </section>

    <button class="save" type="submit">Save</button>
    <div class="savenote">Saves every tab.</div>
  </form>
  <script>
    (function(){
      // Tabs. All panes stay in ONE form so a single Save keeps every field;
      // the tabs only show and hide them. The open tab is kept in the URL
      // hash so a reload (or the redirect after an error) lands back on it.
      var tabs=[].slice.call(document.querySelectorAll('[role=tab]'));
      function show(id, focus){
        tabs.forEach(function(t){
          var on = t.id === id;
          t.setAttribute('aria-selected', on ? 'true' : 'false');
          t.tabIndex = on ? 0 : -1;
          document.getElementById(t.getAttribute('aria-controls')).hidden = !on;
          if (on && focus) t.focus();
        });
        try { history.replaceState(null, '', '#' + id.replace('tab-','')); } catch(e) {}
      }
      tabs.forEach(function(t, i){
        t.addEventListener('click', function(){ show(t.id); });
        t.addEventListener('keydown', function(e){
          var n = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
          if (e.key === 'Home') { show(tabs[0].id, true); e.preventDefault(); }
          else if (e.key === 'End') { show(tabs[tabs.length-1].id, true); e.preventDefault(); }
          else if (n) { show(tabs[(i + n + tabs.length) % tabs.length].id, true); e.preventDefault(); }
        });
      });
      var h = (location.hash || '').slice(1);
      if (h && document.getElementById('tab-' + h)) show('tab-' + h);
      // A field that fails validation on a hidden tab would block Save with
      // no visible reason: switch to its tab so the browser can point at it.
      document.getElementById('settingsForm').addEventListener('invalid', function(e){
        var pane = e.target.closest('[role=tabpanel]');
        if (pane && pane.hidden) show(pane.getAttribute('aria-labelledby'));
      }, true);

      // Overlay IP prefix follows the subnet (Network tab).
      var cidr=document.getElementById('overlay_cidr'), pre=document.getElementById('ipprefix'), oct=document.getElementById('last_octet');
      function upd(){ var p=((cidr.value||'10.22.55.0/24').split('/')[0]).split('.'); pre.textContent = p.length>=3 ? (p[0]+'.'+p[1]+'.'+p[2]+'.') : ''; }
      cidr.addEventListener('input', upd);
      oct.addEventListener('input', function(){ this.value=this.value.replace(/[^0-9]/g,'').slice(0,3); });
      upd();

      // Public exit needs the DHT and the public relay.
      var px=document.getElementById('public_exit'), lim=document.getElementById('public_exit_limits'), hint=document.getElementById('public_exit_hint');
      var dht=document.querySelector('input[name=dht]'), pr=document.querySelector('input[name=public_relay]');
      function sync(){
        var ok = dht.checked && pr.checked;
        px.disabled = !ok;
        if (!ok) px.checked = false;
        lim.style.display = px.checked ? '' : 'none';
        hint.style.opacity = ok ? '1' : '.6';
      }
      [px,dht,pr].forEach(function(e){ e.addEventListener('change', sync); });
      sync();
    })();
  </script>
</body></html>`

const savedPage = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Saved</title>
<style>body{background:#000;color:#fff;font:16px/1.6 -apple-system,system-ui,sans-serif;display:flex;height:100vh;margin:0;align-items:center;justify-content:center}
@media (prefers-color-scheme: light){body{background:#fff;color:#000}}</style></head>
<body><div style="text-align:center"><h2>Settings saved ✓</h2><p>You can close this tab and click <b>Connect</b> in the menu bar.</p></div></body></html>`
