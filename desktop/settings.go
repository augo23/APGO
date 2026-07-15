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

func openSettingsWindow() {
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
			if err := saveSettingsForm(r); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "<p>Save failed: %s</p>", html.EscapeString(err.Error()))
				return
			}
			fmt.Fprint(w, savedPage)
			notify("Settings saved. Click Connect to join.")
			go func() { time.Sleep(400 * time.Millisecond); finish() }()
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, settingsPage(loadConfig()))
	})

	srv := &http.Server{Handler: mux}
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
func saveSettingsForm(r *http.Request) error {
	_ = r.ParseForm()
	c := loadConfig()
	c.NetworkName = strings.TrimSpace(r.FormValue("network_name"))
	c.PSK = strings.TrimSpace(r.FormValue("psk"))
	c.FriendlyName = strings.TrimSpace(r.FormValue("friendly_name"))
	// Post-quantum is controlled network-wide from the Security policy page
	// (one place), not here — leave c.PostQuantum as loaded (default on).
	c.IPv6 = r.FormValue("ipv6") == "on"
	c.UseExit = r.FormValue("use_exit") == "on"
	c.ExitPeer = strings.TrimSpace(r.FormValue("exit_peer"))
	c.OverlayCIDR = strings.TrimSpace(r.FormValue("overlay_cidr"))
	if c.OverlayCIDR == "" {
		c.OverlayCIDR = "10.28.55.0/24"
	}
	if p, err := strconv.Atoi(strings.TrimSpace(r.FormValue("port"))); err == nil && p > 0 {
		c.UDPListenPort = p
	} else {
		c.UDPListenPort = 6969
	}
	c.Tun.AddressCIDR = overlayAddrFromInput(r.FormValue("last_octet"), c.OverlayCIDR)
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
				return fmt.Errorf("the network admin passwords don't match — type the same one in both boxes")
			}
			pub, err := genAdminKey(pw)
			if err != nil {
				return err
			}
			c.AdminPublicKey = pub
			notify("Admin key created — distributing it to your devices.")
		}
	} else if np := r.FormValue("admin_new_password"); np != "" {
		if np != r.FormValue("admin_new_password_confirm") {
			return fmt.Errorf("the new network admin passwords don't match — type the same one in both boxes")
		}
		if err := changeAdminPassword(r.FormValue("admin_current_password"), np); err != nil {
			return err
		}
		notify("Network admin password changed — redistributing the key.")
	}

	applyDefaults(&c)
	if err := saveConfig(c); err != nil {
		return err
	}
	// Every settings save with a network name registers/updates that network's
	// switchable profile — this is how new networks are added: just enter the
	// new name + PSK and Save, then switch between them in the tray's
	// "Networks" submenu.
	registerCurrentProfileUI()
	return nil
}

func settingsPage(c mConfig) string {
	port := "6969"
	if c.UDPListenPort > 0 {
		port = strconv.Itoa(c.UDPListenPort)
	}
	cidr := c.OverlayCIDR
	if cidr == "" {
		cidr = "10.28.55.0/24"
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
	useExitChecked := ""
	if c.UseExit {
		useExitChecked = "checked"
	}
	return strings.NewReplacer(
		"{{NETWORK}}", html.EscapeString(c.NetworkName),
		"{{PSK}}", html.EscapeString(c.PSK),
		"{{FRIENDLY}}", html.EscapeString(c.FriendlyName),
		"{{IPV6CHECK}}", ipv6Checked,
		"{{USEEXITCHECK}}", useExitChecked,
		"{{EXITPEER}}", html.EscapeString(c.ExitPeer),
		"{{CIDR}}", html.EscapeString(cidr),
		"{{PORT}}", html.EscapeString(port),
		"{{LASTOCTET}}", html.EscapeString(lastOctet),
		"{{RENDEZVOUS}}", html.EscapeString(strings.Join(c.RendezvousServers, ", ")),
		"{{ADMINSECTION}}", adminSectionHTML(),
	).Replace(settingsTmpl)
}

// adminSectionHTML renders the admin-key part of the settings form: a create
// field when the network has no admin key yet, or the read-only current key
// (to copy onto other nodes) when one exists.
func adminSectionHTML() string {
	if adminKeyAvailable() {
		pub := currentNetworkAdminPub()
		body := `<label>Network admin key</label>
    <div class="hint">This network has an admin key. It's distributed (encrypted) to every device, so you can manage nodes from any device with the network admin password.</div>`
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
  body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;display:flex;justify-content:center;padding:28px}
  form{width:100%;max-width:460px;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:26px}
  h1{font-size:18px;margin:0 0 4px}
  p.sub{margin:0 0 18px;color:var(--muted);font-size:13px}
  label{display:block;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin:16px 0 6px}
  input{width:100%;padding:11px 12px;background:var(--field);color:var(--fg);border:1px solid var(--line);border-radius:10px;font-size:15px;outline:none}
  input:focus{border-color:var(--accent)}
  .pskrow{position:relative}
  .toggle{position:absolute;right:10px;top:9px;font-size:12px;color:var(--muted);background:none;border:0;cursor:pointer}
  .genbtn{margin-top:8px;padding:9px 14px;font-size:13px;font-weight:600;color:var(--fg);background:var(--field);border:1px solid var(--line);border-radius:10px;cursor:pointer}
  .genbtn:hover{border-color:var(--accent)}
  .hint{color:var(--muted);font-size:12px;margin-top:6px}
  button.save{width:100%;margin-top:22px;padding:12px;border:0;border-radius:10px;background:var(--accent);color:var(--bg);font-size:15px;font-weight:600;cursor:pointer}
  a.backtop{display:inline-block;margin:0 0 14px;color:var(--fg);font-size:13px;font-weight:600;text-decoration:none;border:1px solid var(--line);padding:7px 14px;border-radius:10px}
</style></head>
<body>
  <form method="POST" autocomplete="off">
    <a class="backtop" href="/">← Back</a>
    <h1>APGO Settings</h1>
    <p class="sub">Use the same values on every node in your network.</p>

    <label for="network_name">Network name</label>
    <input id="network_name" name="network_name" type="text" value="{{NETWORK}}" spellcheck="false" autocapitalize="off">

    <label for="psk">Pre-shared key</label>
    <div class="pskrow">
      <input id="psk" name="psk" type="password" value="{{PSK}}" spellcheck="false" autocapitalize="off">
      <button type="button" class="toggle" onclick="var p=document.getElementById('psk');p.type=p.type==='password'?'text':'password';this.textContent=p.type==='password'?'Show':'Hide'">Show</button>
    </div>
    <button type="button" class="genbtn" onclick="var b=new Uint8Array(32);crypto.getRandomValues(b);document.getElementById('psk').value='base64:'+btoa(String.fromCharCode.apply(null,b))">Generate a random key</button>
    <div class="hint">Click Generate to make a random key, or paste one. Use the SAME key on every device.</div>

    <label for="friendly_name">This device's name (optional)</label>
    <input id="friendly_name" name="friendly_name" type="text" value="{{FRIENDLY}}" spellcheck="false" autocapitalize="off">
    <div class="hint">A friendly label shown next to this device in the admin panel.</div>

    <label for="overlay_cidr">Overlay subnet (CIDR)</label>
    <input id="overlay_cidr" name="overlay_cidr" type="text" value="{{CIDR}}" spellcheck="false">

    <label for="last_octet">This node's overlay IP (optional)</label>
    <div style="display:flex;align-items:center;gap:8px">
      <span id="ipprefix" style="color:var(--muted);font-family:ui-monospace,Menlo,monospace;white-space:nowrap">10.28.55.</span>
      <input id="last_octet" name="last_octet" type="text" inputmode="numeric" maxlength="3" value="{{LASTOCTET}}" style="max-width:96px" spellcheck="false">
    </div>
    <div class="hint">Type just the last number (1–254). Blank = auto-assign. The prefix follows the subnet above.</div>

    <label style="display:flex;align-items:center;gap:8px;margin-top:14px;text-transform:none;letter-spacing:0">
      <input type="checkbox" name="use_exit" {{USEEXITCHECK}} style="width:auto"> Full VPN — route all traffic via an exit node
    </label>
    <div class="hint">Sends ALL of this device's internet traffic through an exit node on your mesh (a Linux node with <b>EXIT_NODE=1</b>). Encrypted device→exit; traffic leaves the internet from the exit's IP. Applies on reconnect.</div>

    <label for="exit_peer">Exit node (blank = fastest)</label>
    <input id="exit_peer" name="exit_peer" type="text" value="{{EXITPEER}}" spellcheck="false" autocapitalize="off" placeholder="auto — fastest exit">
    <div class="hint">Leave blank to auto-pick the fastest reachable exit (re-probed every ~5 min, switches if it goes down). Or pin ONE node — by overlay IP (e.g. 10.28.55.7), device name, or key fingerprint — to always egress there; traffic pauses rather than re-routing if it's offline.</div>

    <label style="display:flex;align-items:center;gap:8px;margin-top:14px;text-transform:none;letter-spacing:0">
      <input type="checkbox" name="ipv6" {{IPV6CHECK}} style="width:auto"> IPv6 dual-stack transport
    </label>
    <div class="hint">Connects directly over IPv6 where available (no NAT) — fixes hotspot/CGNAT reachability. The overlay stays IPv4. Applies on reconnect.</div>

    <label for="port">UDP listen port</label>
    <input id="port" name="port" type="number" value="{{PORT}}" min="1" max="65535">

    <label for="rendezvous">Discovery servers (optional)</label>
    <input id="rendezvous" name="rendezvous" type="text" value="{{RENDEZVOUS}}" spellcheck="false" autocapitalize="off" placeholder="https://rv.example.com">
    <div class="hint">For networks that block BitTorrent. Comma-separated HTTP(S) rendezvous URLs (see rendezvous/). Leave blank to use trackers.</div>

    {{ADMINSECTION}}

    <button class="save" type="submit">Save</button>

    <div style="border-top:1px solid var(--line);margin-top:22px;padding-top:16px">
      <div class="hint" style="margin-bottom:8px">More:</div>
      <a href="/network" style="color:var(--fg)">Security policy &amp; identity rotation →</a><br>
      <a href="/trackers" style="color:var(--fg)">Trackers →</a><br>
      <a href="/account" style="color:var(--fg)">Dashboard login (account) →</a>
    </div>
  </form>
  <script>
    (function(){
      var cidr=document.getElementById('overlay_cidr'), pre=document.getElementById('ipprefix'), oct=document.getElementById('last_octet');
      function upd(){ var p=((cidr.value||'10.28.55.0/24').split('/')[0]).split('.'); pre.textContent = p.length>=3 ? (p[0]+'.'+p[1]+'.'+p[2]+'.') : ''; }
      cidr.addEventListener('input', upd);
      oct.addEventListener('input', function(){ this.value=this.value.replace(/[^0-9]/g,'').slice(0,3); });
      upd();
    })();
  </script>
</body></html>`

const savedPage = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Saved</title>
<style>body{background:#000;color:#fff;font:16px/1.6 -apple-system,system-ui,sans-serif;display:flex;height:100vh;margin:0;align-items:center;justify-content:center}
@media (prefers-color-scheme: light){body{background:#fff;color:#000}}</style></head>
<body><div style="text-align:center"><h2>Settings saved ✓</h2><p>You can close this tab and click <b>Connect</b> in the menu bar.</p></div></body></html>`
