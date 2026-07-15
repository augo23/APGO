package main

// features.go adds three admin capabilities, all rendered as in-page styled
// forms (no browser pop-ups):
//   - device approval (admission control): approve/deny pending devices
//   - network rotation: change the network name + PSK (compromise recovery)
//   - tracker management: add / remove BitTorrent trackers live
//
// Signing happens here (with the admin password) and the signed record is handed
// to the local client, which floods it across the mesh.

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
)

// --- device approval -----------------------------------------------------

func handleAPIApprove(w http.ResponseWriter, r *http.Request) {
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
		Action   string `json:"action"` // "approve" | "deny"
		Password string `json:"password"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
	if json.Unmarshal(body, &req) != nil || req.PubKey == "" {
		http.Error(w, "bad request (device public key required)", http.StatusBadRequest)
		return
	}
	if req.Action != "approve" && req.Action != "deny" {
		req.Action = "approve"
	}
	if !adminKeyAvailable() {
		http.Error(w, "No admin key exists yet. Create one on the Admin key page.", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		http.Error(w, "admin password required", http.StatusUnauthorized)
		return
	}
	rec, err := signApproval(req.Password, req.PubKey, req.Action)
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
	code, resp, err := ctlPost("/api/approve-signed", recBytes)
	proxyJSON(w, code, resp, err)
}

// --- network rotation (name + PSK) ---------------------------------------

// handleAPISetIPv6 proxies the per-node IPv6 transport toggle to the client
// control socket. Local per-node setting; applies on the node's next restart.
func handleAPISetIPv6(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Requested-With") != "overlay-admin" {
		http.Error(w, "missing X-Requested-With header", http.StatusBadRequest)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	code, resp, err := ctlPost("/api/set-ipv6", body)
	proxyJSON(w, code, resp, err)
}

func handleAPINetwork(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Requested-With") != "overlay-admin" {
		http.Error(w, "missing X-Requested-With header", http.StatusBadRequest)
		return
	}
	var req struct {
		NetworkName string `json:"network_name"`
		PSK         string `json:"psk"`
		Password    string `json:"password"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
	if json.Unmarshal(body, &req) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.NetworkName = strings.TrimSpace(req.NetworkName)
	req.PSK = strings.TrimSpace(req.PSK)
	if req.NetworkName == "" || req.PSK == "" {
		http.Error(w, "both a network name and a PSK are required", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(req.PSK, "base64:") {
		http.Error(w, "PSK must start with base64: (use Generate to make one)", http.StatusBadRequest)
		return
	}
	if !adminKeyAvailable() {
		http.Error(w, "No admin key exists yet. Create one on the Admin key page.", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		http.Error(w, "admin password required", http.StatusUnauthorized)
		return
	}
	rec, err := signNetworkConfig(req.Password, req.NetworkName, req.PSK)
	if err == errWrongPassword {
		http.Error(w, "incorrect admin password", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "signing failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	recBytes, _ := json.Marshal(rec)
	code, resp, err := ctlPost("/api/network-config-signed", recBytes)
	proxyJSON(w, code, resp, err)
}

// handleAPIPolicy toggles a network-wide policy (post-quantum on/off) with the
// admin password; the signed policy is applied live on every node.
func handleAPIPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Requested-With") != "overlay-admin" {
		http.Error(w, "missing X-Requested-With header", http.StatusBadRequest)
		return
	}
	var req struct {
		PubKey      string `json:"pubkey"` // "" = network-wide
		PostQuantum bool   `json:"post_quantum"`
		Password    string `json:"password"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
	if json.Unmarshal(body, &req) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !adminKeyAvailable() {
		http.Error(w, "No admin key exists yet. Create one on the Admin key page.", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		http.Error(w, "admin password required", http.StatusUnauthorized)
		return
	}
	rec, err := signNetworkPolicy(req.Password, req.PubKey, req.PostQuantum)
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
	code, resp, err := ctlPost("/api/policy-signed", recBytes)
	proxyJSON(w, code, resp, err)
}

func handleNetworkPage(w http.ResponseWriter, r *http.Request) {
	if !authed(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	current := ""
	pq := false
	if _, b, err := ctlGet("/api/join-info"); err == nil {
		var m struct {
			NetworkName string `json:"network_name"`
		}
		if json.Unmarshal(b, &m) == nil {
			current = m.NetworkName
		}
	}
	ipv6 := true
	if _, b, err := ctlGet("/api/info"); err == nil {
		var m struct {
			PostQuantum bool `json:"post_quantum"`
			IPv6        bool `json:"ipv6"`
		}
		if json.Unmarshal(b, &m) == nil {
			pq = m.PostQuantum
			ipv6 = m.IPv6
		}
	}
	fmt.Fprint(w, networkPage(current, pq, ipv6))
}

func networkPage(current string, pq, ipv6 bool) string {
	pqChecked := ""
	if pq {
		pqChecked = "checked"
	}
	ipv6Checked := ""
	if ipv6 {
		ipv6Checked = "checked"
	}
	return pageShell("Settings", `
  <h1>Transport</h1>
  <p class="sub">IPv6 dual-stack transport. Where a node has a routable IPv6 address (many home ISPs and phone hotspots), peers connect directly over v6 with no NAT — this is what fixes CGNAT/hotspot reachability. The overlay itself stays IPv4. Per-node setting; applies to THIS node on its next restart.</p>
  <label style="display:flex;align-items:center;gap:8px;text-transform:none;letter-spacing:0">
    <input id="ipv6" type="checkbox" `+ipv6Checked+` style="width:auto" onchange="setIPv6()"> IPv6 dual-stack transport
  </label>
  <p id="imsg" class="msg"></p>

  <hr style="border:0;border-top:1px solid var(--line);margin:26px 0">

  <h1>Security policy</h1>
  <p class="sub">Toggle the hybrid post-quantum layer (ML-KEM-768) for the WHOLE network with the network admin password. It applies live to every device on every platform — no reconnect. Slightly slower; safe to roll out (peers negotiate automatically).</p>
  <label style="display:flex;align-items:center;gap:8px;text-transform:none;letter-spacing:0">
    <input id="pq" type="checkbox" `+pqChecked+` style="width:auto"> Post-quantum encryption (network-wide)
  </label>
  <label>Network admin password</label>
  <input id="pqpw" type="password">
  <button type="button" class="primary" onclick="applyPolicy()">Apply security policy</button>
  <p id="pmsg" class="msg"></p>

  <hr style="border:0;border-top:1px solid var(--line);margin:26px 0">

  <h1>Rotate network identity</h1>
  <p class="sub">Rotate the network name and PSK — every approved device receives the change and reconnects. Use this if the network is ever compromised. Devices that are offline or removed will not follow.</p>
  <p class="warn">Changing these briefly disconnects the whole mesh while nodes reconnect under the new identity.</p>

  <label>New network name</label>
  <input id="netname" type="text" spellcheck="false" value="`+html.EscapeString(current)+`">

  <label>New pre-shared key</label>
  <div class="row">
    <input id="psk" type="text" spellcheck="false" placeholder="base64:…">
    <button type="button" class="gen" onclick="genPsk()">Generate</button>
  </div>

  <label>Network admin password</label>
  <input id="pw" type="password">

  <button type="button" class="primary" onclick="rotate()">Apply rotation</button>
  <p id="msg" class="msg"></p>

  <hr style="border:0;border-top:1px solid var(--line);margin:26px 0">
  <h1>More settings</h1>
  <p class="sub"><a href="/adminkey">Network admin key &amp; password →</a></p>
  <p class="sub"><a href="/trackers">Trackers →</a></p>
  <p class="sub"><a href="/account">Dashboard login (account) →</a></p>
`, `
async function setIPv6(){
  const msg=document.getElementById('imsg'); msg.textContent='Saving…';
  const on=document.getElementById('ipv6').checked;
  const r=await fetch('/api/set-ipv6',{method:'POST',headers:{'Content-Type':'application/json','X-Requested-With':'overlay-admin'},
    body:JSON.stringify({enabled:on})});
  const t=await r.text();
  msg.textContent = r.ok ? ('IPv6 '+(on?'enabled':'disabled')+' — restart this node to apply.') : ('Failed: '+t);
  msg.style.color = r.ok ? '#38c172' : '#e6b400';
}
function genPsk(){
  const b=new Uint8Array(32); crypto.getRandomValues(b);
  let s=btoa(String.fromCharCode.apply(null,b));
  document.getElementById('psk').value='base64:'+s;
}
async function applyPolicy(){
  const msg=document.getElementById('pmsg'); msg.textContent='Signing + distributing…';
  const r=await fetch('/api/policy',{method:'POST',headers:{'Content-Type':'application/json','X-Requested-With':'overlay-admin'},
    body:JSON.stringify({post_quantum:document.getElementById('pq').checked,password:document.getElementById('pqpw').value})});
  const t=await r.text();
  msg.textContent = r.ok ? 'Security policy applied network-wide.' : ('Failed: '+t);
  msg.style.color = r.ok ? '#38c172' : '#e6b400';
  document.getElementById('pqpw').value='';
}
async function rotate(){
  const msg=document.getElementById('msg'); msg.textContent='Signing + distributing…';
  const r=await fetch('/api/network',{method:'POST',headers:{'Content-Type':'application/json','X-Requested-With':'overlay-admin'},
    body:JSON.stringify({network_name:document.getElementById('netname').value,psk:document.getElementById('psk').value,password:document.getElementById('pw').value})});
  const t=await r.text();
  msg.textContent = r.ok ? 'Rotation sent. Devices will reconnect under the new identity shortly.' : ('Failed: '+t);
  msg.style.color = r.ok ? '#38c172' : '#e6b400';
}
`)
}

// --- tracker management --------------------------------------------------

func handleAPITrackers(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if r.Header.Get("X-Requested-With") != "overlay-admin" {
			http.Error(w, "missing X-Requested-With header", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
		code, resp, err := ctlPost("/api/trackers", body)
		proxyJSON(w, code, resp, err)
		return
	}
	code, resp, err := ctlGet("/api/trackers")
	proxyJSON(w, code, resp, err)
}

func handleTrackersPage(w http.ResponseWriter, r *http.Request) {
	if !authed(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, trackersPage())
}

func trackersPage() string {
	return pageShell("Trackers", `
  <h1>Torrent trackers</h1>
  <p class="sub">These trackers help nodes discover each other. One tracker per line, separated by one blank line — edit the box to add or remove them. Changes apply within a minute, no restart.</p>
  <textarea id="trk" spellcheck="false" placeholder="udp://tracker.example.org:6969/announce

udp://tracker.opentrackr.org:1337/announce" style="width:100%;height:220px;background:var(--field);color:var(--fg);border:1px solid var(--line);border-radius:10px;padding:11px 12px;font-family:ui-monospace,Menlo,monospace;font-size:13px;outline:none"></textarea>
  <button type="button" class="primary" onclick="saveT()" style="margin-top:14px">Save changes</button>
  <p id="msg" class="msg"></p>
  <p class="sub" style="margin-top:18px"><a href="/network">← Back to Settings</a></p>
`, `
async function load(){
  const r=await fetch('/api/trackers',{headers:{'X-Requested-With':'overlay-admin'}});
  const j=await r.json(); document.getElementById('trk').value=(j.trackers||[]).join('\n\n');
}
async function saveT(){
  const msg=document.getElementById('msg'); msg.textContent='Saving…';
  const list=document.getElementById('trk').value.split('\n').map(s=>s.trim()).filter(s=>s.length>0);
  const r=await fetch('/api/trackers',{method:'POST',headers:{'Content-Type':'application/json','X-Requested-With':'overlay-admin'},
    body:JSON.stringify({trackers:list})});
  const j=await r.json().catch(()=>({}));
  if(r.ok){document.getElementById('trk').value=(j.trackers||list).join('\n\n');msg.textContent='Saved.';msg.style.color='#38c172';}
  else{msg.textContent='Save failed: '+(await r.text().catch(()=>''));msg.style.color='#e6b400';}
}
load();
`)
}

// pageShell wraps body + script in the shared dark-themed page used across the
// admin panel.
func pageShell(title, body, script string) string {
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>APGO — ` + html.EscapeString(title) + `</title>
<link rel="icon" type="image/svg+xml" href="/static/logo.svg">
<style>
  :root{--bg:#000;--panel:#0c0c0c;--fg:#fff;--muted:#9aa0a6;--line:#242424;--accent:#fff;--field:#111}
  @media (prefers-color-scheme:light){:root{--bg:#fff;--panel:#f6f6f6;--fg:#0a0a0a;--muted:#5f6368;--line:#e2e2e2;--accent:#000;--field:#fff}}
  *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,system-ui,sans-serif;display:flex;justify-content:center;padding:28px}
  .card{width:100%;max-width:560px;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:26px}
  h1{font-size:19px;margin:0 0 4px}p.sub{color:var(--muted);font-size:13px;margin:4px 0 14px}
  p.warn{color:#e6b400;font-size:12px;margin:0 0 16px}
  label{display:block;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin:16px 0 6px}
  input{width:100%;padding:11px 12px;background:var(--field);color:var(--fg);border:1px solid var(--line);border-radius:10px;font-size:15px;outline:none}
  input:focus{border-color:var(--accent)}
  .row{display:flex;gap:8px}.row input{flex:1}
  button{cursor:pointer;border:0;border-radius:10px;font-size:14px;font-weight:600}
  .gen{padding:0 16px;background:var(--field);color:var(--fg);border:1px solid var(--line)}
  .primary{width:100%;margin-top:22px;padding:12px;background:var(--accent);color:var(--bg)}
  .msg{font-size:13px;margin-top:10px;min-height:1em}
  .tlist{margin:6px 0 12px}
  .trow{display:flex;align-items:center;gap:8px;padding:8px 10px;border:1px solid var(--line);border-radius:9px;margin-bottom:6px}
  .turl{flex:1;font-size:13px;word-break:break-all}
  .rm{background:transparent;color:#e06c6c;border:1px solid var(--line);padding:5px 10px}
  a.back{display:inline-block;margin-top:18px;color:var(--muted);font-size:13px;text-decoration:none;border:1px solid var(--line);padding:9px 16px;border-radius:10px}
  a.backtop{display:inline-block;margin:0 0 16px;color:var(--fg);font-size:13px;font-weight:600;text-decoration:none;border:1px solid var(--line);padding:7px 14px;border-radius:10px}
</style></head><body>
  <div class="card">
    <a class="backtop" href="/">← Back</a>
` + body + `
    <div><a class="back" href="/">← Back to dashboard</a></div>
  </div>
<script>
` + script + `
</script>
</body></html>`
}
