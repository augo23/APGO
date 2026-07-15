// overlay-admin is a small, standalone web dashboard for an APGO node. It runs
// in its own container, reads the client's logs and live session list, and can
// revoke (kick) a connected peer. It talks to the client over a unix-domain
// socket on a shared volume — it never opens a network connection to the
// client. Access to the dashboard itself is gated by a username/password
// supplied through the compose environment.
package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed static
var staticFS embed.FS

var (
	adminUser     = env("ADMIN_USER", "admin")
	adminPass     = os.Getenv("ADMIN_PASSWORD")
	listenAddr    = env("ADMIN_LISTEN", ":8088")
	controlSocket = env("CONTROL_SOCKET", "/shared/control.sock")
	logFile       = env("LOG_FILE", "/shared/overlay-client.log")
	tlsCert       = os.Getenv("ADMIN_TLS_CERT")
	tlsKey        = os.Getenv("ADMIN_TLS_KEY")
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	// One-time setup: `overlay-admin genkey` creates the password-encrypted
	// admin signing key and prints the public key to distribute to nodes.
	if len(os.Args) > 1 && os.Args[1] == "genkey" {
		runGenKey()
		return
	}

	initBootstrap()
	loadLoginThrottle() // restore brute-force backoff state across restarts
	if bootstrapPassword != "" {
		log.Println("============================================================")
		log.Println("[admin] No dashboard login is configured yet.")
		log.Printf("[admin]   Temporary login -> username: %q  password: %s", adminUser, bootstrapPassword)
		log.Println("[admin]   Sign in with these; you'll be asked to set your own password.")
		log.Println("============================================================")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/setup", handleSetup)
	mux.HandleFunc("/logout", handleLogout)
	mux.HandleFunc("/static/", handleStatic) // public assets (logo) for the login page
	mux.HandleFunc("/favicon.ico", handleFavicon)
	mux.HandleFunc("/api/info", requireAuthAPI(handleAPIInfo))
	mux.HandleFunc("/api/config", requireAuthAPI(handleAPIConfig))
	mux.HandleFunc("/api/sessions", requireAuthAPI(handleAPISessions))
	mux.HandleFunc("/api/revocations", requireAuthAPI(handleAPIRevocations))
	mux.HandleFunc("/api/revoke", requireAuthAPI(handleAPIRevoke))
	mux.HandleFunc("/api/provision", requireAuthAPI(handleAPIProvision))
	mux.HandleFunc("/api/logs", requireAuthAPI(handleAPILogs))
	mux.HandleFunc("/account", handleAccount)
	mux.HandleFunc("/adminkey", handleAdminKey)
	mux.HandleFunc("/qr", handleQR)
	mux.HandleFunc("/network", handleNetworkPage)
	mux.HandleFunc("/trackers", handleTrackersPage)
	mux.HandleFunc("/api/approve", requireAuthAPI(handleAPIApprove))
	mux.HandleFunc("/api/network", requireAuthAPI(handleAPINetwork))
	mux.HandleFunc("/api/set-ipv6", requireAuthAPI(handleAPISetIPv6))
	mux.HandleFunc("/api/trackers", requireAuthAPI(handleAPITrackers))
	mux.HandleFunc("/api/policy", requireAuthAPI(handleAPIPolicy))
	mux.HandleFunc("/network-setup", handleNetworkSetup)
	mux.HandleFunc("/", handleIndex)

	// If we hold the admin key locally, distribute the encrypted blob to our
	// client so it (and every node) can trust + store it.
	if adminKeyConfigured() {
		go func() {
			if akf, err := loadAdminKeyFile(); err == nil {
				distributeSealedKey(akf)
			}
		}()
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	if tlsCert != "" && tlsKey != "" {
		log.Printf("overlay-admin listening on %s (https)", listenAddr)
		log.Fatal(srv.ListenAndServeTLS(tlsCert, tlsKey))
	}
	log.Printf("overlay-admin listening on %s (http) — put it behind TLS or an SSH tunnel for real use", listenAddr)
	log.Fatal(srv.ListenAndServe())
}

// --- sessions (login cookie -> expiry) -----------------------------------

type sessionStore struct {
	mu sync.Mutex
	m  map[string]time.Time
}

var sessions = &sessionStore{m: map[string]time.Time{}}

const sessionTTL = 8 * time.Hour

func (s *sessionStore) create() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	s.m[tok] = time.Now().Add(sessionTTL)
	s.mu.Unlock()
	return tok
}

func (s *sessionStore) valid(tok string) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[tok]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.m, tok)
		return false
	}
	return true
}

func (s *sessionStore) destroy(tok string) {
	s.mu.Lock()
	delete(s.m, tok)
	s.mu.Unlock()
}

func authed(r *http.Request) bool {
	c, err := r.Cookie("sid")
	if err != nil {
		return false
	}
	return sessions.valid(c.Value)
}

// --- client control-socket proxy -----------------------------------------

func ctlClient() *http.Client {
	return &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", controlSocket)
			},
		},
	}
}

func ctlGet(path string) (int, []byte, error) {
	resp, err := ctlClient().Get("http://unix" + path)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, b, nil
}

func ctlPost(path string, body []byte) (int, []byte, error) {
	resp, err := ctlClient().Post("http://unix"+path, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, nil
}

// --- middleware & pages ---------------------------------------------------

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func requireAuthAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !authed(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if mustSetup() {
		// Signed in with the temporary password — force setting a real one.
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if clientNeedsSetup() {
		// The overlay node has no network config yet — configure it from the web.
		http.Redirect(w, r, "/network-setup", http.StatusSeeOther)
		return
	}
	serveEmbedded(w, "static/index.html", "text/html; charset=utf-8")
}

// clientNeedsSetup reports whether the overlay client is unconfigured (waiting
// for its network name + PSK).
func clientNeedsSetup() bool {
	code, body, err := ctlGet("/api/info")
	if err != nil || code != 200 {
		return false
	}
	var m struct {
		NeedsSetup bool `json:"needs_setup"`
	}
	return json.Unmarshal(body, &m) == nil && m.NeedsSetup
}

// handleNetworkSetup shows a first-run network setup form (parity with the macOS
// app's settings window) and posts it to the client's setup API.
func handleNetworkSetup(w http.ResponseWriter, r *http.Request) {
	if !authed(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		payload, _ := json.Marshal(map[string]any{
			"network_name":  strings.TrimSpace(r.FormValue("network_name")),
			"psk":           strings.TrimSpace(r.FormValue("psk")),
			"overlay_cidr":  strings.TrimSpace(r.FormValue("overlay_cidr")),
			"friendly_name": strings.TrimSpace(r.FormValue("friendly_name")),
			"address":       strings.TrimSpace(r.FormValue("address")),
			"post_quantum":  r.FormValue("post_quantum") == "on",
		})
		code, body, err := ctlPost("/api/setup", payload)
		if err != nil || code != 200 {
			msg := "the client isn't reachable"
			if err == nil {
				msg = strings.TrimSpace(string(body))
			}
			fmt.Fprint(w, networkSetupPage("Setup failed: "+msg))
			return
		}
		// The client persists the config and restarts; bounce back to the
		// dashboard shortly.
		fmt.Fprint(w, `<!DOCTYPE html><meta charset="utf-8"><meta http-equiv="refresh" content="6;url=/">
<body style="background:#000;color:#fff;font:15px/1.6 system-ui;display:flex;height:100vh;margin:0;align-items:center;justify-content:center;text-align:center">
<div><h2>Network configured ✓</h2><p>The node is restarting to apply it. Returning to the dashboard…</p></div></body>`)
		return
	}
	fmt.Fprint(w, networkSetupPage(""))
}

func networkSetupPage(msg string) string {
	banner := ""
	if msg != "" {
		banner = `<p class="msg">` + html.EscapeString(msg) + `</p>`
	}
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>APGO — network setup</title>
<link rel="icon" type="image/svg+xml" href="/static/logo.svg">
<style>
  :root{--bg:#000;--panel:#0c0c0c;--fg:#fff;--muted:#9aa0a6;--line:#242424;--accent:#fff;--field:#111}
  @media (prefers-color-scheme:light){:root{--bg:#fff;--panel:#f6f6f6;--fg:#0a0a0a;--muted:#5f6368;--line:#e2e2e2;--accent:#000;--field:#fff}}
  *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,system-ui,sans-serif;display:flex;justify-content:center;padding:28px}
  form{width:100%;max-width:460px;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:26px}
  .brand{display:flex;flex-direction:column;align-items:center;gap:10px;margin-bottom:6px}.brand img{width:52px;height:52px;border-radius:13px}
  h1{font-size:18px;margin:0;text-align:center}p.sub{color:var(--muted);font-size:13px;text-align:center;margin:6px 0 4px}
  label{display:block;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin:16px 0 6px}
  input{width:100%;padding:11px 12px;background:var(--field);color:var(--fg);border:1px solid var(--line);border-radius:10px;font-size:15px;outline:none}
  input:focus{border-color:var(--accent)}.hint{color:var(--muted);font-size:12px;margin-top:6px}
  button{width:100%;margin-top:22px;padding:12px;border:0;border-radius:10px;background:var(--accent);color:var(--bg);font-size:15px;font-weight:600;cursor:pointer}
  .msg{color:#e6b400;font-size:13px;text-align:center;margin-top:10px}
</style></head><body>
<form method="POST" autocomplete="off">
  <div class="brand"><img src="/static/logo.svg" alt="APGO"><h1>Set up this node</h1></div>
  <p class="sub">Use the SAME network name and PSK on every device in your network.</p>

  <label for="network_name">Network name</label>
  <input id="network_name" name="network_name" type="text" spellcheck="false" autocapitalize="off" autofocus>

  <label for="psk">Pre-shared key</label>
  <div style="display:flex;gap:8px">
    <input id="psk" name="psk" type="text" spellcheck="false" autocapitalize="off" placeholder="base64:…  (leave blank to generate one)" style="flex:1">
    <button type="button" onclick="genPsk()" style="width:auto;margin-top:0;padding:0 16px;background:var(--field);color:var(--fg);border:1px solid var(--line)">Generate</button>
  </div>
  <div class="hint">Paste your existing <code>base64:</code> key, click Generate to make one, or leave blank to auto-generate. Use the SAME key on every device.</div>
  <script>function genPsk(){var b=new Uint8Array(32);crypto.getRandomValues(b);document.getElementById('psk').value='base64:'+btoa(String.fromCharCode.apply(null,b));}</script>

  <label for="overlay_cidr">Overlay subnet (CIDR)</label>
  <input id="overlay_cidr" name="overlay_cidr" type="text" value="10.28.55.0/24" spellcheck="false">

  <label for="address">Overlay IP for THIS node (optional)</label>
  <input id="address" name="address" type="text" spellcheck="false" placeholder="blank = auto-assign, or e.g. 10.28.55.5/24">

  <label for="friendly_name">Friendly name (optional)</label>
  <input id="friendly_name" name="friendly_name" type="text" spellcheck="false">

  <label style="display:flex;align-items:center;gap:8px;text-transform:none;letter-spacing:0;margin-top:14px">
    <input type="checkbox" name="post_quantum" style="width:auto"> Post-quantum encryption (hybrid ML-KEM-768)
  </label>
  <div class="hint">Future-proofs against quantum computers. Slightly slower; enable on every device.</div>

  <button type="submit">Save &amp; connect</button>
</form>` + banner + `</body></html>`
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if authed(r) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		serveEmbedded(w, "static/login.html", "text/html; charset=utf-8")
	case http.MethodPost:
		// Per-IP brute-force backoff: after a few failures a source must wait.
		ip := clientIP(r)
		if ok, wait := loginAllowed(ip); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
			http.Redirect(w, r, "/login?e=2", http.StatusSeeOther)
			return
		}
		_ = r.ParseForm()
		u := r.FormValue("username")
		p := r.FormValue("password")
		if !checkLogin(u, p) {
			loginFailed(ip)
			http.Redirect(w, r, "/login?e=1", http.StatusSeeOther)
			return
		}
		loginSucceeded(ip)
		http.SetCookie(w, &http.Cookie{
			Name:     "sid",
			Value:    sessions.create(),
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   tlsCert != "",
			MaxAge:   int(sessionTTL.Seconds()),
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSetup is the one-time create-account page, shown only while no login
// exists (blank compose credentials and no saved credentials file).
func handleSetup(w http.ResponseWriter, r *http.Request) {
	if !authed(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !mustSetup() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		u := strings.TrimSpace(r.FormValue("username"))
		p := r.FormValue("password")
		if u == "" || len(p) < 6 {
			fmt.Fprint(w, setupPage("Enter a username and a password of at least 6 characters."))
			return
		}
		nc, err := newCreds(u, p)
		if err == nil {
			err = saveCreds(nc)
		}
		if err != nil {
			fmt.Fprint(w, setupPage("Could not save: "+err.Error()))
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: "sid", Value: sessions.create(), Path: "/", HttpOnly: true,
			SameSite: http.SameSiteStrictMode, Secure: tlsCert != "", MaxAge: int(sessionTTL.Seconds()),
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	fmt.Fprint(w, setupPage(""))
}

func setupPage(msg string) string {
	banner := ""
	if msg != "" {
		banner = `<p class="msg">` + html.EscapeString(msg) + `</p>`
	}
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>APGO — create login</title><link rel="icon" type="image/svg+xml" href="/static/logo.svg">
<style>
  :root{--bg:#000;--panel:#0c0c0c;--fg:#fff;--muted:#9aa0a6;--line:#242424;--accent:#fff;--field:#111}
  @media (prefers-color-scheme:light){:root{--bg:#fff;--panel:#f6f6f6;--fg:#0a0a0a;--muted:#5f6368;--line:#e2e2e2;--accent:#000;--field:#fff}}
  *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,system-ui,sans-serif;display:flex;justify-content:center;padding:28px}
  form{width:100%;max-width:400px;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:26px}
  .brand{display:flex;flex-direction:column;align-items:center;gap:10px;margin-bottom:10px}.brand img{width:52px;height:52px;border-radius:13px}
  h1{font-size:18px;margin:0;text-align:center}label{display:block;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin:14px 0 6px}
  input{width:100%;padding:11px 12px;background:var(--field);color:var(--fg);border:1px solid var(--line);border-radius:10px;font-size:15px;outline:none}
  input:focus{border-color:var(--accent)}button{width:100%;margin-top:20px;padding:12px;border:0;border-radius:10px;background:var(--accent);color:var(--bg);font-size:15px;font-weight:600;cursor:pointer}
  .sub{color:var(--muted);font-size:13px;text-align:center;margin:0 0 6px}.msg{color:#e6b400;font-size:13px;text-align:center}
</style></head><body>
<form method="POST" autocomplete="off">
  <div class="brand"><img src="/static/logo.svg" alt="APGO"><h1>Create dashboard login</h1></div>
  <p class="sub">You're signed in with the temporary password. Now set your own username and password.</p>
  <label>Username</label><input name="username" value="` + html.EscapeString(adminUser) + `" autofocus spellcheck="false" autocapitalize="off">
  <label>Password</label><input name="password" type="password">
  <button type="submit">Create</button>` + banner + `
</form></body></html>`
}

// handleAdminKey lets an authenticated operator create the network admin
// signing key from the web UI (if none exists yet) and shows the public key.
// The key is then auto-seeded to all peers.
func handleAdminKey(w http.ResponseWriter, r *http.Request) {
	if !authed(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		// Change password if a usable signing key is present; otherwise create one.
		if r.FormValue("new_password") != "" || adminKeyAvailable() {
			if r.FormValue("new_password") != r.FormValue("confirm_password") {
				fmt.Fprint(w, adminKeyPage("The new passwords don't match — type the same password in both boxes."))
				return
			}
			if err := changeAdminPassword(r.FormValue("current_password"), r.FormValue("new_password")); err != nil {
				fmt.Fprint(w, adminKeyPage(err.Error()))
				return
			}
			fmt.Fprint(w, adminKeyPage("Network admin password changed — the re-encrypted key is being distributed to every node."))
			return
		}
		if r.FormValue("password") != r.FormValue("confirm_password") {
			fmt.Fprint(w, adminKeyPage("The passwords don't match — type the same password in both boxes."))
			return
		}
		if _, err := genAdminKey(r.FormValue("password")); err != nil {
			fmt.Fprint(w, adminKeyPage(err.Error()))
			return
		}
		fmt.Fprint(w, adminKeyPage("Admin key created — the encrypted key is being distributed to every node."))
		return
	}
	fmt.Fprint(w, adminKeyPage(""))
}

func adminKeyPage(msg string) string {
	banner := ""
	if msg != "" {
		banner = `<p class="msg">` + html.EscapeString(msg) + `</p>`
	}
	inner := ""
	if akf, ok := currentAdminKeyFile(); ok && akf.PublicKey != "" {
		inner = `<p class="sub">The network admin key is set up and distributed (encrypted) to every node, so you can sign from any node with the network admin password. Its public key:</p>
  <textarea readonly onclick="this.select()">ADMIN_PUBLIC_KEY=` + html.EscapeString(akf.PublicKey) + `</textarea>
  <p class="sub" style="margin-top:18px">Change the network admin password (re-encrypts and re-distributes the key):</p>
  <label>Current network admin password</label><input name="current_password" type="password">
  <label>New network admin password (min 8 characters)</label><input name="new_password" type="password">
  <label>Confirm new network admin password</label><input name="confirm_password" type="password">
  <button type="submit">Change network admin password</button>`
	} else {
		note := ""
		if networkHasAdminKey() {
			// A public key is trusted but the encrypted signing key isn't here.
			note = `<p class="msg">This node trusts an admin key but the encrypted signing key hasn't reached it. If the network already has one, it should sync within a few keepalive cycles once connected. If this is a fresh network (or a leftover key from a previous one), create a new key below — it will replace the trusted one.</p>`
		}
		inner = `<p class="sub">No network admin key here yet. Create one to enable signed, network-wide revocations, approvals, and IP/name changes — the encrypted key is distributed to every node so you can manage from anywhere with the <b>network admin password</b>. This is separate from your dashboard login.</p>
  <label>Set the network admin password (min 8 characters)</label><input name="password" type="password" autofocus>
  <label>Confirm the network admin password</label><input name="confirm_password" type="password">
  <button type="submit">Create network admin key</button>` + note
	}
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>APGO — admin key</title><link rel="icon" type="image/svg+xml" href="/static/logo.svg">
<style>
  :root{--bg:#000;--panel:#0c0c0c;--fg:#fff;--muted:#9aa0a6;--line:#242424;--accent:#fff;--field:#111}
  @media (prefers-color-scheme:light){:root{--bg:#fff;--panel:#f6f6f6;--fg:#0a0a0a;--muted:#5f6368;--line:#e2e2e2;--accent:#000;--field:#fff}}
  *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,system-ui,sans-serif;display:flex;justify-content:center;padding:28px}
  .card{width:100%;max-width:460px;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:26px}
  .brand{display:flex;flex-direction:column;align-items:center;gap:10px;margin-bottom:8px}.brand img{width:52px;height:52px;border-radius:13px}
  h1{font-size:18px;margin:0;text-align:center}label{display:block;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin:14px 0 6px}
  input{width:100%;padding:11px 12px;background:var(--field);color:var(--fg);border:1px solid var(--line);border-radius:10px;font-size:15px;outline:none}
  textarea{width:100%;height:70px;background:var(--field);color:var(--fg);border:1px solid var(--line);border-radius:10px;padding:10px;font-family:ui-monospace,Menlo,monospace}
  input:focus{border-color:var(--accent)}button{width:100%;margin-top:18px;padding:12px;border:0;border-radius:10px;background:var(--accent);color:var(--bg);font-size:15px;font-weight:600;cursor:pointer}
  .sub{color:var(--muted);font-size:13px}.msg{color:#e6b400;font-size:13px;text-align:center}a{color:var(--muted)}
 a.backtop{display:inline-block;margin:0 0 14px;color:var(--fg);font-size:13px;font-weight:600;text-decoration:none;border:1px solid var(--line);padding:7px 14px;border-radius:10px}
</style></head><body>
<div class="card">
  <a class="backtop" href="/">← Back</a>
  <div class="brand"><img src="/static/logo.svg" alt="APGO"><h1>Admin key</h1></div>
  <form method="POST" autocomplete="off">` + inner + `</form>` + banner + `
  <p style="margin-top:14px;text-align:center"><a href="/">← Back to dashboard</a></p>
</div></body></html>`
}

func handleAccount(w http.ResponseWriter, r *http.Request) {
	if !authed(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		cur := r.FormValue("current_password")
		nu := strings.TrimSpace(r.FormValue("new_username"))
		np := r.FormValue("new_password")
		if nu == "" || len(np) < 6 {
			fmt.Fprint(w, accountPage("Username is required and the new password must be at least 6 characters."))
			return
		}
		if !verifyCurrentPassword(cur) {
			fmt.Fprint(w, accountPage("Current password is incorrect."))
			return
		}
		nc, err := newCreds(nu, np)
		if err == nil {
			err = saveCreds(nc)
		}
		if err != nil {
			fmt.Fprint(w, accountPage("Could not save: "+err.Error()))
			return
		}
		fmt.Fprint(w, accountPage("Saved. Sign out and back in with the new credentials."))
		return
	}
	fmt.Fprint(w, accountPage(""))
}

func accountPage(msg string) string {
	banner := ""
	if msg != "" {
		banner = `<p class="msg">` + html.EscapeString(msg) + `</p>`
	}
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>APGO — account</title><link rel="icon" type="image/svg+xml" href="/static/logo.svg">
<style>
  :root{--bg:#000;--panel:#0c0c0c;--fg:#fff;--muted:#9aa0a6;--line:#242424;--accent:#fff;--field:#111}
  @media (prefers-color-scheme:light){:root{--bg:#fff;--panel:#f6f6f6;--fg:#0a0a0a;--muted:#5f6368;--line:#e2e2e2;--accent:#000;--field:#fff}}
  *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,system-ui,sans-serif;display:flex;justify-content:center;padding:28px}
  form{width:100%;max-width:400px;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:26px}
  h1{font-size:18px;margin:0 0 16px}label{display:block;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin:14px 0 6px}
  input{width:100%;padding:11px 12px;background:var(--field);color:var(--fg);border:1px solid var(--line);border-radius:10px;font-size:15px;outline:none}
  input:focus{border-color:var(--accent)}button{width:100%;margin-top:20px;padding:12px;border:0;border-radius:10px;background:var(--accent);color:var(--bg);font-size:15px;font-weight:600;cursor:pointer}
  .msg{color:#e6b400;font-size:13px}a{color:var(--muted)}
</style></head><body>
<form method="POST" autocomplete="off">
  <h1>Change dashboard login</h1>` + banner + `
  <label>Current password</label><input name="current_password" type="password" autofocus>
  <label>New username</label><input name="new_username" value="` + html.EscapeString(currentUsername()) + `" spellcheck="false" autocapitalize="off">
  <label>New password</label><input name="new_password" type="password">
  <button type="submit">Save</button>
  <p style="margin-top:14px"><a href="/">← Back to dashboard</a></p>
</form></body></html>`
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("sid"); err == nil {
		sessions.destroy(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleStatic(w http.ResponseWriter, r *http.Request) {
	// Only the logo is public (the login page needs it before auth).
	if strings.TrimPrefix(r.URL.Path, "/static/") == "logo.svg" {
		serveEmbedded(w, "static/logo.svg", "image/svg+xml")
		return
	}
	http.NotFound(w, r)
}

func handleFavicon(w http.ResponseWriter, r *http.Request) {
	serveEmbedded(w, "static/logo.svg", "image/svg+xml")
}

func serveEmbedded(w http.ResponseWriter, name, ctype string) {
	b, err := staticFS.ReadFile(name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", ctype)
	_, _ = w.Write(b)
}

// --- API ------------------------------------------------------------------

func handleAPIInfo(w http.ResponseWriter, r *http.Request) {
	code, body, err := ctlGet("/api/info")
	proxyJSON(w, code, body, err)
}

func handleAPISessions(w http.ResponseWriter, r *http.Request) {
	code, body, err := ctlGet("/api/sessions")
	proxyJSON(w, code, body, err)
}

func handleAPIConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"admin_configured": adminKeyAvailable()})
}

func handleAPIRevocations(w http.ResponseWriter, r *http.Request) {
	code, body, err := ctlGet("/api/revocations")
	proxyJSON(w, code, body, err)
}

// pushAdminPubKey tells our client the admin public key so it seeds it to peers.
// Retries because the client control socket may not be up yet at startup.
func pushAdminPubKey() {
	akf, err := loadAdminKeyFile()
	if err != nil || akf.PublicKey == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{"pubkey": akf.PublicKey})
	for i := 0; i < 15; i++ {
		if code, _, err := ctlPost("/api/set-admin-pubkey", body); err == nil && code == http.StatusOK {
			return
		}
		time.Sleep(2 * time.Second)
	}
}

// handleAPIRevoke signs a revoke/restore record with the admin key (gated by
// the operator's password) and hands it to the client to verify, apply, and
// propagate. If no admin key has been set up yet it falls back to an unsigned,
// local-only kick so the button still does something during initial setup.
func handleAPIRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Requested-With") != "overlay-admin" {
		http.Error(w, "missing X-Requested-With header", http.StatusBadRequest)
		return
	}
	var req struct {
		Remote   string `json:"remote"`
		PubKey   string `json:"pubkey"`
		Password string `json:"password"`
		Action   string `json:"action"`
		Local    bool   `json:"local"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
	if json.Unmarshal(body, &req) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Accept of a LOCAL (unsigned) revocation — no signing or password needed.
	if req.Action == "restore" && req.Local {
		if req.PubKey == "" {
			http.Error(w, "peer public key required", http.StatusBadRequest)
			return
		}
		b, _ := json.Marshal(map[string]string{"pubkey": req.PubKey})
		code, resp, err := ctlPost("/api/local-restore", b)
		proxyJSON(w, code, resp, err)
		return
	}

	if adminKeyAvailable() {
		if req.PubKey == "" {
			http.Error(w, "peer public key required", http.StatusBadRequest)
			return
		}
		if req.Password == "" {
			http.Error(w, "admin password required", http.StatusUnauthorized)
			return
		}
		action := "revoke"
		if req.Action == "restore" {
			action = "restore"
		}
		rec, err := signRevocation(req.Password, req.PubKey, action)
		if err == errWrongPassword {
			http.Error(w, "incorrect admin password", http.StatusUnauthorized)
			return
		}
		if err != nil {
			http.Error(w, "signing failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if akf, ok := currentAdminKeyFile(); ok {
			distributeSealedKey(akf)
		}
		recBytes, _ := json.Marshal(rec)
		code, resp, err := ctlPost("/api/revoke-signed", recBytes)
		proxyJSON(w, code, resp, err)
		return
	}

	// No admin key yet — fall back to an unsigned local kick.
	if req.Remote == "" {
		http.Error(w, "admin key not configured; run `overlay-admin genkey` to enable network-wide revocation", http.StatusBadRequest)
		return
	}
	b, _ := json.Marshal(map[string]string{"remote": req.Remote})
	code, resp, err := ctlPost("/api/revoke", b)
	proxyJSON(w, code, resp, err)
}

// handleAPIProvision signs an overlay-address / friendly-name assignment for a
// target node (gated by the operator's password) and hands it to the client to
// verify, apply, and gossip across the mesh. Requires an admin key.
func handleAPIProvision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Requested-With") != "overlay-admin" {
		http.Error(w, "missing X-Requested-With header", http.StatusBadRequest)
		return
	}
	var req struct {
		PubKey   string `json:"pubkey"`
		Address  string `json:"address"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
	if json.Unmarshal(body, &req) != nil || req.PubKey == "" {
		http.Error(w, "bad request (peer public key required)", http.StatusBadRequest)
		return
	}
	if !adminKeyAvailable() {
		http.Error(w, "No admin key exists on this network yet. Create one on the Admin key page.", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		http.Error(w, "admin password required", http.StatusUnauthorized)
		return
	}
	if req.Address == "" && req.Name == "" {
		http.Error(w, "nothing to change (provide an address, a name, or both)", http.StatusBadRequest)
		return
	}
	rec, err := signProvision(req.Password, req.PubKey, strings.TrimSpace(req.Address), strings.TrimSpace(req.Name))
	if err == errWrongPassword {
		http.Error(w, "incorrect admin password", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "signing failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Make sure the client trusts + holds the admin key so it can verify the
	// signed provision (harmless if it already does).
	if akf, ok := currentAdminKeyFile(); ok {
		distributeSealedKey(akf)
	}
	recBytes, _ := json.Marshal(rec)
	code, resp, err := ctlPost("/api/provision-signed", recBytes)
	proxyJSON(w, code, resp, err)
}

func handleAPILogs(w http.ResponseWriter, r *http.Request) {
	tail := 200
	if v := r.URL.Query().Get("tail"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 2000 {
			tail = n
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"lines": tailFile(logFile, 512<<10, tail)})
}

func proxyJSON(w http.ResponseWriter, code int, body []byte, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"client control socket unavailable"}`))
		return
	}
	if code == 0 {
		code = http.StatusOK
	}
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// tailFile returns up to maxLines of the last maxBytes of a file, dropping a
// possibly-partial first line when the file was truncated to the byte window.
func tailFile(path string, maxBytes int64, maxLines int) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{}
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return []string{}
	}
	start := int64(0)
	if st.Size() > maxBytes {
		start = st.Size() - maxBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return []string{}
	}
	data, _ := io.ReadAll(f)
	text := strings.TrimRight(string(data), "\n")
	if text == "" {
		return []string{}
	}
	lines := strings.Split(text, "\n")
	if start > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines
}
