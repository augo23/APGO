package main

// qr.go renders a password-gated "join QR" for the admin dashboard. Scanning it
// with the APGO iOS/Android app joins the network with no typing.
//
// The QR encodes a small JSON payload with the network name, PSK, overlay subnet
// and any rendezvous servers. Because it contains the PSK it is ONLY reachable
// behind the admin login (authed) — it is never exposed unauthenticated.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"

	qrcode "github.com/skip2/go-qrcode"
)

// joinPayload is the exact JSON the mobile apps parse when they scan the QR.
// It carries the full crypto profile (cipher + post-quantum settings), not just
// the PSK — every one of these must match on all nodes or handshakes fail
// silently, so joining by QR configures all of them at once.
type joinPayload struct {
	Kind              string   `json:"kind"` // "apgo-join" — lets the scanner sanity-check
	NetworkName       string   `json:"network_name"`
	PSK               string   `json:"psk"`
	OverlayCIDR       string   `json:"overlay_cidr"`
	RendezvousServers []string `json:"rendezvous_servers,omitempty"`
	Trackers          []string `json:"trackers,omitempty"` // top trackers so a scanned device shares this network's discovery
	Cipher            string   `json:"cipher,omitempty"`   // "chacha" or "aesgcm"
	PostQuantum       *bool    `json:"post_quantum,omitempty"`
	PQAuth            *bool    `json:"pq_auth,omitempty"`
}

// buildJoinPayload fetches the join details from the local client control socket
// and returns the compact JSON that goes into the QR.
func buildJoinPayload() ([]byte, joinPayload, error) {
	code, body, err := ctlGet("/api/join-info")
	if err != nil || code != 200 {
		if err == nil {
			err = fmt.Errorf("client returned HTTP %d", code)
		}
		return nil, joinPayload{}, err
	}
	var src struct {
		NetworkName       string   `json:"network_name"`
		PSK               string   `json:"psk"`
		OverlayCIDR       string   `json:"overlay_cidr"`
		RendezvousServers []string `json:"rendezvous_servers"`
		Trackers          []string `json:"trackers"`
		Cipher            string   `json:"cipher"`
		PostQuantum       *bool    `json:"post_quantum"`
		PQAuth            *bool    `json:"pq_auth"`
	}
	if err := json.Unmarshal(body, &src); err != nil {
		return nil, joinPayload{}, err
	}
	jp := joinPayload{
		Kind:              "apgo-join",
		NetworkName:       src.NetworkName,
		PSK:               src.PSK,
		OverlayCIDR:       src.OverlayCIDR,
		RendezvousServers: src.RendezvousServers,
		Trackers:          src.Trackers,
		Cipher:            src.Cipher,
		PostQuantum:       src.PostQuantum,
		PQAuth:            src.PQAuth,
	}
	out, err := json.Marshal(jp)
	return out, jp, err
}

func handleQR(w http.ResponseWriter, r *http.Request) {
	if !authed(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// The QR encodes the network PSK — require re-entering the admin username +
	// password before revealing it.
	if r.Method != http.MethodPost {
		fmt.Fprint(w, qrAuthForm(""))
		return
	}
	_ = r.ParseForm()
	if !checkLogin(r.FormValue("username"), r.FormValue("password")) {
		fmt.Fprint(w, qrAuthForm("Incorrect username or password."))
		return
	}

	payload, jp, err := buildJoinPayload()
	if err != nil || jp.NetworkName == "" || jp.PSK == "" {
		msg := "the overlay node isn't configured yet (no network name / PSK)."
		if err != nil {
			msg = html.EscapeString(err.Error())
		}
		fmt.Fprint(w, qrPage("", "", msg))
		return
	}

	png, err := qrcode.Encode(string(payload), qrcode.Medium, 512)
	if err != nil {
		fmt.Fprint(w, qrPage("", "", "could not render the QR code: "+html.EscapeString(err.Error())))
		return
	}
	dataURI := "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	fmt.Fprint(w, qrPage(dataURI, html.EscapeString(jp.NetworkName), ""))
}

// qrAuthForm asks for the admin username + password before the QR is shown.
func qrAuthForm(msg string) string {
	banner := ""
	if msg != "" {
		banner = `<p class="msg">` + html.EscapeString(msg) + `</p>`
	}
	return pageShell("Join QR", `
  <h1>Confirm admin credentials</h1>
  <p class="sub">The join QR contains your network's pre-shared key. Re-enter your admin username and password to reveal it.</p>
  <form method="POST" autocomplete="off">
    <label>Username</label>
    <input name="username" type="text" autocomplete="off" spellcheck="false" autofocus>
    <label>Password</label>
    <input name="password" type="password" autocomplete="off">
    <button type="submit" class="primary">Show join QR</button>
    `+banner+`
  </form>
`, ``)
}

func qrPage(dataURI, network, msg string) string {
	body := ""
	if dataURI != "" {
		body = `<img class="qr" src="` + dataURI + `" alt="Join QR code" width="300" height="300">
    <p class="net">Network: <strong>` + network + `</strong></p>
    <p class="warn">Anyone who scans this joins your network. Treat it like a password — don't screenshot or share it.</p>`
	} else {
		body = `<p class="msg">` + msg + `</p>`
	}
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>APGO — join QR</title>
<link rel="icon" type="image/svg+xml" href="/static/logo.svg">
<style>
  :root{--bg:#000;--panel:#0c0c0c;--fg:#fff;--muted:#9aa0a6;--line:#242424;--accent:#fff}
  @media (prefers-color-scheme:light){:root{--bg:#fff;--panel:#f6f6f6;--fg:#0a0a0a;--muted:#5f6368;--line:#e2e2e2;--accent:#000}}
  *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,system-ui,sans-serif;display:flex;justify-content:center;padding:28px}
  .card{width:100%;max-width:420px;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:26px;text-align:center}
  .brand{display:flex;flex-direction:column;align-items:center;gap:10px;margin-bottom:12px}.brand img{width:52px;height:52px;border-radius:13px}
  h1{font-size:18px;margin:0}p.sub{color:var(--muted);font-size:13px;margin:6px 0 16px}
  .qr{background:#fff;border-radius:12px;padding:12px;width:300px;height:300px;image-rendering:pixelated}
  .net{margin:14px 0 4px;font-size:14px}.warn{color:#e6b400;font-size:12px;margin:8px 0 0}
  .msg{color:#e6b400;font-size:14px}
  a.back{display:inline-block;margin-top:18px;color:var(--muted);font-size:13px;text-decoration:none;border:1px solid var(--line);padding:9px 16px;border-radius:10px}
</style></head><body>
  <div class="card">
    <div class="brand"><img src="/static/logo.svg" alt="APGO"><h1>Join this network</h1></div>
    <p class="sub">In the APGO app, tap <strong>Scan QR</strong> and point it here.</p>
    ` + body + `
    <div><a class="back" href="/">← Back to dashboard</a></div>
  </div>
</body></html>`
}
