package main

// adminpanel.go serves the full APGO admin dashboard locally (the same UI as
// the Docker web dashboard) and proxies its API calls to the Mac client's
// control socket. It's bound to 127.0.0.1 and gated by a per-launch token that
// becomes a cookie, so the dashboard's own fetches authenticate automatically.
// Revoke/restore work the same as on Linux: local kicks need no key; signed
// network revocations use the local admin key (Set up admin key…).

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed webui
var webuiFS embed.FS

var adminAddr string // host:port

var (
	adminSess   = map[string]time.Time{}
	adminSessMu sync.Mutex
)

func startAdminServer() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return
	}
	adminAddr = ln.Addr().String()

	mux := http.NewServeMux()

	// Public assets (needed by the login/setup pages before auth).
	mux.HandleFunc("/static/logo.svg", func(w http.ResponseWriter, r *http.Request) { serveWebUI(w, "webui/logo.svg", "image/svg+xml") })
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { serveWebUI(w, "webui/logo.svg", "image/svg+xml") })

	// Auth pages.
	mux.HandleFunc("/setup", handleSetup)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sid"); err == nil {
			adminSessMu.Lock()
			delete(adminSess, c.Value)
			adminSessMu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	mux.HandleFunc("/account", requirePage(handleAccount))

	// Dashboard + gated pages.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		requirePage(func(w http.ResponseWriter, r *http.Request) {
			serveWebUI(w, "webui/index.html", "text/html; charset=utf-8")
		})(w, r)
	})
	mux.HandleFunc("/adminkey", requirePage(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, adminKeyPageHTML())
	}))
	mux.HandleFunc("/qr", requirePage(handleQRPage))
	mux.HandleFunc("/network", requirePage(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, networkPageHTML())
	}))
	mux.HandleFunc("/trackers", requirePage(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, trackersPageHTML())
	}))
	mux.HandleFunc("/api/approve", apiAuth(handleAdminApprove))
	mux.HandleFunc("/api/network", apiAuth(handleAdminNetwork))
	mux.HandleFunc("/api/trackers", apiAuth(handleAdminTrackers))
	mux.HandleFunc("/api/policy", apiAuth(handleAdminPolicy))
	// Connect / disconnect the local overlay client from the dashboard.
	mux.HandleFunc("/api/connect", apiAuth(func(w http.ResponseWriter, r *http.Request) {
		go doConnect()
		writeJSON(w, map[string]any{"ok": true})
	}))
	mux.HandleFunc("/api/disconnect", apiAuth(func(w http.ResponseWriter, r *http.Request) {
		go doDisconnect()
		writeJSON(w, map[string]any{"ok": true})
	}))
	mux.HandleFunc("/settings", requirePage(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := saveSettingsForm(r); err != nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "<p>Save failed: %s</p>", htmlEsc(err.Error()))
				return
			}
			notify("Settings saved. Reconnect to apply.")
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, settingsPage(loadConfig()))
	}))

	// API (session-gated).
	mux.HandleFunc("/api/config", apiAuth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"admin_configured": adminKeyAvailable()})
	}))
	mux.HandleFunc("/api/info", apiAuth(func(w http.ResponseWriter, r *http.Request) { proxyCtl(w, "GET", "/api/info", nil) }))
	mux.HandleFunc("/api/sessions", apiAuth(func(w http.ResponseWriter, r *http.Request) { proxyCtl(w, "GET", "/api/sessions", nil) }))
	mux.HandleFunc("/api/revocations", apiAuth(func(w http.ResponseWriter, r *http.Request) { proxyCtl(w, "GET", "/api/revocations", nil) }))
	mux.HandleFunc("/api/logs", apiAuth(handleAdminLogs))
	mux.HandleFunc("/api/revoke", apiAuth(handleAdminRevoke))
	mux.HandleFunc("/api/provision", apiAuth(handleAdminProvision))

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
}

func openAdminPanel() {
	if adminAddr == "" {
		notify("Admin panel isn't ready yet.")
		return
	}
	openBrowser("http://" + adminAddr + "/")
}

func openAdminKeyPage() {
	if adminAddr == "" {
		return
	}
	openBrowser("http://" + adminAddr + "/adminkey")
}

// pushAdminPubKey tells the local running client the admin public key so it
// auto-seeds it to peers. Best-effort (the client may not be connected yet).
func pushAdminPubKey(pub string) {
	if pub == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{"pubkey": pub})
	_, _, _ = ctlDo("POST", "/api/set-admin-pubkey", body)
}

// setupAdminKey creates the network admin signing key (or shows the existing
// public key). Run it once, then put the shown ADMIN_PUBLIC_KEY on every node.
func setupAdminKey() {
	if adminKeyAvailable() {
		openAdminKeyPage()
		return
	}
	pw := promptPassword("Set a password for the network admin signing key (min 8 chars):")
	if pw == "" {
		return
	}
	pub, err := genAdminKey(pw)
	if err != nil {
		notify("Admin key: " + err.Error())
		return
	}
	// Store the public key in the config (so the client trusts + auto-seeds it
	// on the next connect) and push it to a running client now.
	c := loadConfig()
	c.AdminPublicKey = pub
	_ = saveConfig(c)
	go pushAdminPubKey(pub)
	notify("Admin key created — it will be seeded to your peers.")
	openAdminKeyPage()
}

// --- auth helpers --------------------------------------------------------

func newAdminSession() string {
	tok := randToken()
	adminSessMu.Lock()
	adminSess[tok] = time.Now().Add(12 * time.Hour)
	adminSessMu.Unlock()
	return tok
}

func adminAuthed(r *http.Request) bool {
	c, err := r.Cookie("sid")
	if err != nil {
		return false
	}
	adminSessMu.Lock()
	defer adminSessMu.Unlock()
	exp, ok := adminSess[c.Value]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(adminSess, c.Value)
		return false
	}
	return true
}

func setSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: newAdminSession(), Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func apiAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !adminAuthed(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// requirePage gates an HTML page: first run → /setup, else not logged in → /login.
func requirePage(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !credsConfigured() {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		if !adminAuthed(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if !credsConfigured() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		if c, ok := loadCreds(); ok && c.matches(r.FormValue("username"), r.FormValue("password")) {
			setSessionCookie(w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/login?e=1", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, loginPage(r.URL.Query().Has("e")))
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
	if credsConfigured() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
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
		setSessionCookie(w)
		// First-run: after creating the admin username/password, go straight to
		// network Settings so the user configures the network before the dashboard.
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	fmt.Fprint(w, setupPage(""))
}

func handleAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		if !verifyCurrentPassword(r.FormValue("current_password")) {
			fmt.Fprint(w, accountPage("Current password is incorrect."))
			return
		}
		u := strings.TrimSpace(r.FormValue("new_username"))
		p := r.FormValue("new_password")
		if u == "" || len(p) < 6 {
			fmt.Fprint(w, accountPage("Username is required and the new password must be at least 6 characters."))
			return
		}
		nc, err := newCreds(u, p)
		if err == nil {
			err = saveCreds(nc)
		}
		if err != nil {
			fmt.Fprint(w, accountPage("Could not save: "+err.Error()))
			return
		}
		fmt.Fprint(w, accountPage("Saved. Use the new credentials next time you sign in."))
		return
	}
	fmt.Fprint(w, accountPage(""))
}

func authCard(title, inner string) string {
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>APGO — ` + title + `</title>
<link rel="icon" type="image/svg+xml" href="/static/logo.svg">
<style>
  :root{--bg:#000;--panel:#0c0c0c;--fg:#fff;--muted:#9aa0a6;--line:#242424;--accent:#fff;--field:#111}
  @media (prefers-color-scheme:light){:root{--bg:#fff;--panel:#f6f6f6;--fg:#0a0a0a;--muted:#5f6368;--line:#e2e2e2;--accent:#000;--field:#fff}}
  *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,system-ui,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px}
  form{width:100%;max-width:360px;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:28px}
  .brand{display:flex;flex-direction:column;align-items:center;gap:12px;margin-bottom:14px}.brand img{width:56px;height:56px;border-radius:14px}
  h1{font-size:17px;margin:0;text-align:center}label{display:block;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin:14px 0 6px}
  input{width:100%;padding:11px 12px;background:var(--field);color:var(--fg);border:1px solid var(--line);border-radius:10px;font-size:15px;outline:none}
  input:focus{border-color:var(--accent)}button{width:100%;margin-top:20px;padding:12px;border:0;border-radius:10px;background:var(--accent);color:var(--bg);font-size:15px;font-weight:600;cursor:pointer}
  .msg{color:#e6b400;font-size:13px;text-align:center;margin-top:10px}a{color:var(--muted)}
</style></head><body><form method="POST" autocomplete="off">
  <div class="brand"><img src="/static/logo.svg" alt="APGO"><h1>` + title + `</h1></div>
` + inner + `</form></body></html>`
}

func loginPage(showErr bool) string {
	e := ""
	if showErr {
		e = `<p class="msg">Invalid username or password.</p>`
	}
	return authCard("APGO Admin",
		`<label>Username</label><input name="username" autofocus spellcheck="false" autocapitalize="off">
		<label>Password</label><input name="password" type="password">
		<button type="submit">Sign in</button>`+e)
}

func setupPage(msg string) string {
	m := ""
	if msg != "" {
		m = `<p class="msg">` + htmlEsc(msg) + `</p>`
	}
	return authCard("Create dashboard login",
		`<p style="color:var(--muted);font-size:13px;text-align:center;margin:0 0 6px">Set a username and password for this Mac's admin panel.</p>
		<label>Username</label><input name="username" autofocus spellcheck="false" autocapitalize="off">
		<label>Password</label><input name="password" type="password">
		<button type="submit">Create</button>`+m)
}

func accountPage(msg string) string {
	m := ""
	if msg != "" {
		m = `<p class="msg">` + htmlEsc(msg) + `</p>`
	}
	return authCard("Change login",
		`<label>Current password</label><input name="current_password" type="password" autofocus>
		<label>New username</label><input name="new_username" value="`+htmlEsc(currentUsername())+`" spellcheck="false" autocapitalize="off">
		<label>New password</label><input name="new_password" type="password">
		<button type="submit">Save</button>
		<p style="margin-top:12px;text-align:center"><a href="/">← Back to dashboard</a></p>`+m)
}

func serveWebUI(w http.ResponseWriter, name, ctype string) {
	b, err := webuiFS.ReadFile(name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", ctype)
	_, _ = w.Write(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// --- API handlers --------------------------------------------------------

func handleAdminLogs(w http.ResponseWriter, r *http.Request) {
	text := tailLog(logPath(), 256*1024)
	var lines []string
	if strings.TrimSpace(text) != "" {
		lines = strings.Split(strings.TrimRight(text, "\n"), "\n")
	}
	if len(lines) > 400 {
		lines = lines[len(lines)-400:]
	}
	writeJSON(w, map[string]any{"lines": lines})
}

func handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
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

	// Accept of a LOCAL (unsigned) revocation — no signing/password.
	if req.Action == "restore" && req.Local {
		if req.PubKey == "" {
			http.Error(w, "peer public key required", http.StatusBadRequest)
			return
		}
		b, _ := json.Marshal(map[string]string{"pubkey": req.PubKey})
		proxyCtl(w, "POST", "/api/local-restore", b)
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
		if pub := adminPublicKeyB64(); pub != "" {
			pushAdminPubKey(pub)
		}
		recBytes, _ := json.Marshal(rec)
		proxyCtl(w, "POST", "/api/revoke-signed", recBytes)
		return
	}

	// Local kick.
	if req.Remote == "" {
		http.Error(w, "admin key not set up; use \"Set up admin key…\" for network-wide revocation", http.StatusBadRequest)
		return
	}
	b, _ := json.Marshal(map[string]string{"remote": req.Remote})
	proxyCtl(w, "POST", "/api/revoke", b)
}

// handleAdminProvision signs an overlay-address / friendly-name assignment for a
// target node and delivers it to the local client to verify, apply, and gossip.
func handleAdminProvision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
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
		http.Error(w, "peer public key required", http.StatusBadRequest)
		return
	}
	if !adminKeyAvailable() {
		http.Error(w, "No network admin key exists yet. Create one in Settings.", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		http.Error(w, "admin password required", http.StatusUnauthorized)
		return
	}
	if strings.TrimSpace(req.Address) == "" && strings.TrimSpace(req.Name) == "" {
		http.Error(w, "nothing to change", http.StatusBadRequest)
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
	// Make sure the client trusts the admin PUBLIC key so it can verify the
	// signed provision (harmless if it already does).
	if pub := adminPublicKeyB64(); pub != "" {
		pushAdminPubKey(pub)
	}
	recBytes, _ := json.Marshal(rec)
	proxyCtl(w, "POST", "/api/provision-signed", recBytes)
}

// --- control socket proxy ------------------------------------------------

func proxyCtl(w http.ResponseWriter, method, path string, body []byte) {
	code, resp, err := ctlDo(method, path, body)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"client not running"}`))
		return
	}
	if code == 0 {
		code = http.StatusOK
	}
	w.WriteHeader(code)
	_, _ = w.Write(resp)
}

func ctlDo(method, path string, body []byte) (int, []byte, error) {
	cl := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", controlSocket())
			},
		},
	}
	var req *http.Request
	var err error
	if method == "POST" {
		req, err = http.NewRequest("POST", "http://unix"+path, bytes.NewReader(body))
		if req != nil {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		req, err = http.NewRequest("GET", "http://unix"+path, nil)
	}
	if err != nil {
		return 0, nil, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, b, nil
}

// --- admin key page ------------------------------------------------------

func adminKeyPageHTML() string {
	pub := adminPublicKeyB64()
	body := `<p>No admin key is set up on this Mac yet. Use the menu-bar item
	<b>Set up admin key…</b> to create one.</p>`
	if pub != "" {
		body = `<p>Put this on <b>every</b> node (same value everywhere, like the PSK)
		as <code>ADMIN_PUBLIC_KEY</code>, then reconnect, to enable network-wide
		signed revocations:</p>
		<textarea readonly onclick="this.select()" style="width:100%;height:70px">ADMIN_PUBLIC_KEY=` + htmlEsc(pub) + `</textarea>`
	}
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>APGO admin key</title>
<style>body{background:#000;color:#fff;font:15px/1.6 -apple-system,system-ui,sans-serif;max-width:560px;margin:40px auto;padding:0 20px}
@media (prefers-color-scheme: light){body{background:#fff;color:#000}}
code,textarea{font-family:ui-monospace,Menlo,monospace}
textarea{background:#111;color:#fff;border:1px solid #333;border-radius:8px;padding:10px}
@media (prefers-color-scheme: light){textarea{background:#f5f5f5;color:#000;border-color:#ddd}}
h1{font-size:18px}</style></head><body><h1>APGO admin key</h1>` + body + `</body></html>`
}

func htmlEsc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}
