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
	"net/url"
	"strconv"
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
		Net      string `json:"net"` // "" / "main" or a secondary network id
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
	sock, sockErr := netSocketByID(req.Net)
	if sockErr != nil {
		http.Error(w, sockErr.Error(), http.StatusBadRequest)
		return
	}
	recBytes, _ := json.Marshal(rec)
	code, resp, err := ctlPostOn(sock, "/api/approve-signed", recBytes)
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

// handleAPIRendezvousConfig proxies the rendezvous discovery config (server
// list + credential) to/from the local client control socket. GET never
// returns the credential itself, only whether one is set.
func handleAPIRendezvousConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		code, resp, err := ctlGet("/api/rendezvous-config")
		proxyJSON(w, code, resp, err)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Requested-With") != "overlay-admin" {
		http.Error(w, "missing X-Requested-With header", http.StatusBadRequest)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	code, resp, err := ctlPost("/api/rendezvous-config", body)
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
  <h1>This device</h1>
  <p class="sub">Rename this device or move it to a different overlay address. Applies as an admin-signed provision — every node on the mesh learns the change within seconds. (This replaces the old "Edit this device" button on the dashboard.)</p>
  <label>Device name</label>
  <input id="selfName" type="text" spellcheck="false" autocapitalize="off">
  <label>Overlay IP (last octet or full address — blank = keep current)</label>
  <input id="selfIp" type="text" spellcheck="false" autocapitalize="off">
  <label>Network admin password</label>
  <input id="selfPw" type="password">
  <button type="button" class="primary" onclick="saveSelf()">Apply device settings</button>
  <p id="smsg" class="msg"></p>

  <hr style="border:0;border-top:1px solid var(--line);margin:26px 0">

  <h1>Rendezvous discovery</h1>
  <p class="sub">HTTP(S) discovery servers for networks that block BitTorrent — an alternative to trackers. One URL per line. If your server requires a credential, fill in the username and password (HTTP Basic), or put a token in the username box alone (Bearer). Both are included in this network's Join QR, so phones scanning it get working discovery with no typing. Applies to THIS node on its next restart.</p>
  <label>Server URLs</label>
  <textarea id="rvServers" rows="3" spellcheck="false" placeholder="https://rv.example.com"></textarea>
  <label>Username or token (optional)</label>
  <input id="rvUser" type="text" spellcheck="false" autocapitalize="off">
  <label>Password (blank if using a token)</label>
  <input id="rvPass" type="password" autocomplete="off">
  <button type="button" class="primary" onclick="saveRendezvous()">Save rendezvous settings</button>
  <p id="rmsg" class="msg"></p>

  <hr style="border:0;border-top:1px solid var(--line);margin:26px 0">

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

  <h1>Dashboard login</h1>
  <p class="sub">Change the username/password for THIS node's dashboard (separate from the network admin password).</p>
  <label>Current password</label>
  <input id="accCur" type="password" autocomplete="off">
  <label>New username</label>
  <input id="accUser" type="text" spellcheck="false" autocapitalize="off" value="`+html.EscapeString(currentUsername())+`">
  <label>New password (min 6 characters)</label>
  <input id="accPw" type="password" autocomplete="off">
  <label>Confirm new password</label>
  <input id="accPw2" type="password" autocomplete="off">
  <button type="button" class="primary" onclick="saveAccount()">Change dashboard login</button>
  <p id="amsg" class="msg"></p>

  <hr style="border:0;border-top:1px solid var(--line);margin:26px 0">
  <h1>More settings</h1>
  <p class="sub"><a href="/adminkey">Network admin key &amp; password →</a></p>
  <p class="sub"><a href="/trackers">Trackers →</a></p>
`, `
// "This device" — prefill from the client, apply via the same admin-signed
// provision API the per-peer Edit buttons use.
let selfInfo = {pubkey:"", ip:"", name:""};
(async () => {
  try {
    const r = await fetch('/api/info', {headers:{'X-Requested-With':'overlay-admin'}});
    if(!r.ok) return;
    const j = await r.json();
    selfInfo = {pubkey: j.public_key||'', ip: j.overlay_ip||'', name: j.friendly_name||''};
    const n = document.getElementById('selfName');
    if(n && !n.value) n.value = selfInfo.name;
    const ip = document.getElementById('selfIp');
    if(ip) ip.placeholder = selfInfo.ip || 'e.g. 42';
  } catch(e) {}
})();
// Rendezvous discovery — load current config, then save via the client's
// control API. The credential is never echoed back by the server, so the
// password box starts blank and is only sent when the admin types one.
(async () => {
  try {
    const r = await fetch('/api/rendezvous-config', {headers:{'X-Requested-With':'overlay-admin'}});
    if(!r.ok) return;
    const j = await r.json();
    const t = document.getElementById('rvServers');
    if(t) t.value = (j.servers||[]).join('\n');
    const u = document.getElementById('rvUser');
    if(u) u.value = j.auth_user || '';
    if(j.auth_set && !j.auth_user){
      // A bare token is set; show it as configured without revealing it.
      if(u) u.placeholder = '(token configured — type to replace)';
    }
  } catch(e) {}
})();
async function saveRendezvous(){
  const msg = document.getElementById('rmsg');
  msg.textContent='Saving…'; msg.style.color='';
  const servers = document.getElementById('rvServers').value
    .split('\n').map(s=>s.trim()).filter(s=>s);
  const body = JSON.stringify({
    servers,
    user: document.getElementById('rvUser').value.trim(),
    pass: document.getElementById('rvPass').value,
  });
  try {
    const r = await fetch('/api/rendezvous-config', {method:'POST',
      headers:{'Content-Type':'application/json','X-Requested-With':'overlay-admin'}, body});
    const t = await r.text();
    msg.textContent = r.ok
      ? 'Saved — restart this node to start using the new server list.'
      : ('Failed: '+t.trim());
    msg.style.color = r.ok ? '#38c172' : '#e6b400';
    if(r.ok) document.getElementById('rvPass').value='';
  } catch(e) {
    msg.textContent='Request failed — is the client running?'; msg.style.color='#e6b400';
  }
}
async function saveSelf(){
  const msg = document.getElementById('smsg');
  const name = document.getElementById('selfName').value.trim();
  let ip = document.getElementById('selfIp').value.trim();
  const password = document.getElementById('selfPw').value;
  if(!selfInfo.pubkey){ msg.textContent='The client is not connected yet — try again in a moment.'; msg.style.color='#e6b400'; return; }
  if(!name && !ip){ msg.textContent='Enter a device name or an overlay IP.'; msg.style.color='#e6b400'; return; }
  if(!password){ msg.textContent='Network admin password is required.'; msg.style.color='#e6b400'; return; }
  // A bare last-octet is expanded against this node's current subnet prefix.
  if(ip && !ip.includes('.')){
    const b = (selfInfo.ip||'10.22.55.0').split('/')[0].split('.');
    if(b.length >= 3) ip = b[0]+'.'+b[1]+'.'+b[2]+'.'+ip;
  }
  msg.textContent='Applying…'; msg.style.color='';
  try {
    const r = await fetch('/api/provision', {method:'POST',
      headers:{'Content-Type':'application/json','X-Requested-With':'overlay-admin'},
      body: JSON.stringify({pubkey: selfInfo.pubkey, address: ip, name, password})});
    const t = await r.text();
    msg.textContent = r.ok ? 'Applied — the mesh picks it up within seconds.' : ('Failed: '+t.trim());
    msg.style.color = r.ok ? '#38c172' : '#e6b400';
    if(r.ok) document.getElementById('selfPw').value='';
  } catch(e) {
    msg.textContent='Request failed — is the client running?'; msg.style.color='#e6b400';
  }
}
async function saveAccount(){
  const msg=document.getElementById('amsg');
  const pw=document.getElementById('accPw').value;
  if(pw!==document.getElementById('accPw2').value){
    msg.textContent="The new passwords don't match — type the same password in both boxes.";
    msg.style.color='#e6b400'; return;
  }
  msg.textContent='Saving…'; msg.style.color='';
  const body=new URLSearchParams({current_password:document.getElementById('accCur').value,
    new_username:document.getElementById('accUser').value,new_password:pw,new_password2:pw});
  const r=await fetch('/account',{method:'POST',headers:{'X-Requested-With':'overlay-admin'},body});
  const t=await r.text();
  msg.textContent = r.ok ? t : ('Failed: '+t.trim());
  msg.style.color = r.ok ? '#38c172' : '#e6b400';
  if(r.ok){for(const id of ['accCur','accPw','accPw2'])document.getElementById(id).value='';}
}
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
  /* In-page links (e.g. "More settings") follow the theme foreground (white on
     the dark theme) instead of browser-default blue. */
  a{color:var(--fg)}
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

// handleAPINodeConfig signs and forwards a per-node runtime config change.
//
// The panel sends HUMAN rate strings ("5mbit", "200GB", "" = unlimited) and
// tri-state booleans (null = leave unchanged). They are parsed to bytes/sec
// HERE, before signing, so the signature covers the number that will actually
// be enforced on the target node -- if the target re-parsed a string, two nodes
// could disagree about what was signed.
func handleAPINodeConfig(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Requested-With") == "" {
		http.Error(w, "missing X-Requested-With header", http.StatusBadRequest)
		return
	}
	var req struct {
		PubKey       string    `json:"pubkey"` // "" = network-wide
		DHT          *bool     `json:"dht"`
		UseRelays    *bool     `json:"use_public_relays"`
		PublicRelay  *bool     `json:"public_relay"`
		ExitNode     *bool     `json:"exit_node"`
		Trackers       *[]string `json:"trackers"`
		TrackersOn     *bool     `json:"trackers_on"`
		Rendezvous     *string   `json:"rendezvous"`
		RendezvousAuth *string   `json:"rendezvous_auth"`
		RelayUp      *string   `json:"relay_up"`
		RelayDown    *string   `json:"relay_down"`
		RelayQuota   *string   `json:"relay_quota"`
		ExitUp       *string   `json:"exit_up"`
		ExitDown     *string   `json:"exit_down"`
		ExitQuota    *string   `json:"exit_quota"`
		Password     string    `json:"password"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 32768))
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

	rate := func(p *string) *int64 {
		if p == nil {
			return nil
		}
		v := parseAdminRate(*p)
		return &v
	}
	c := SignedNodeConfig{
		PubKey:       req.PubKey,
		DHT:          req.DHT,
		UseRelays:    req.UseRelays,
		PublicRelay:  req.PublicRelay,
		ExitNode:     req.ExitNode,
		Trackers:       req.Trackers,
		TrackersOn:     req.TrackersOn,
		Rendezvous:     req.Rendezvous,
		RendezvousAuth: req.RendezvousAuth,
		RelayUp:      rate(req.RelayUp),
		RelayDown:    rate(req.RelayDown),
		RelayQuota:   rate(req.RelayQuota),
		ExitUp:       rate(req.ExitUp),
		ExitDown:     rate(req.ExitDown),
		ExitQuota:    rate(req.ExitQuota),
	}

	// Refuse an unlimited public relay at the point of signing, not only on the
	// target. Catching it here means the admin gets a sentence explaining the
	// problem while the form is still open, rather than a record that every
	// node silently declines to apply.
	// A blank budget is allowed: the target applies an automatic one (80% of
	// its own estimated capacity). Only the DHT dependency is still a hard
	// requirement, because a relay nobody can discover is simply broken.
	if c.PublicRelay != nil && *c.PublicRelay {
		if c.DHT != nil && !*c.DHT {
			http.Error(w, "the public relay advertises itself through the DHT — enable the DHT too, "+
				"or nobody can find this relay", http.StatusBadRequest)
			return
		}
	}

	rec, err := signNodeConfig(req.Password, c)
	if err == errWrongPassword {
		http.Error(w, "incorrect admin password", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "signing failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	recBytes, _ := json.Marshal(rec)
	code, resp, err := ctlPost("/api/node-config", recBytes)
	proxyJSON(w, code, resp, err)
}

// handleAPINodeConfigGet proxies the read side through to the local client.
func handleAPINodeConfigGet(w http.ResponseWriter, r *http.Request) {
	q := ""
	if pk := r.URL.Query().Get("pubkey"); pk != "" {
		q = "?pubkey=" + url.QueryEscape(pk)
	}
	code, resp, err := ctlGet("/api/node-config" + q)
	proxyJSON(w, code, resp, err)
}

// parseAdminRate mirrors client/bandwidth.go parseRate: "5mbit" / "20MB" /
// "200GB" / "" -> bytes per second (or bytes, for a quota). Bit units are
// divided by 8; byte units are taken as-is. "" and "unlimited" mean 0.
func parseAdminRate(s string) int64 {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "unlimited" || s == "none" || s == "0" {
		return 0
	}
	mult := int64(1)
	bits := false
	switch {
	case strings.HasSuffix(s, "gbit"), strings.HasSuffix(s, "gbps"):
		mult, bits, s = 1e9, true, s[:len(s)-4]
	case strings.HasSuffix(s, "mbit"), strings.HasSuffix(s, "mbps"):
		mult, bits, s = 1e6, true, s[:len(s)-4]
	case strings.HasSuffix(s, "kbit"), strings.HasSuffix(s, "kbps"):
		mult, bits, s = 1e3, true, s[:len(s)-4]
	case strings.HasSuffix(s, "tb"):
		mult, s = 1e12, s[:len(s)-2]
	case strings.HasSuffix(s, "gb"):
		mult, s = 1e9, s[:len(s)-2]
	case strings.HasSuffix(s, "mb"):
		mult, s = 1e6, s[:len(s)-2]
	case strings.HasSuffix(s, "kb"):
		mult, s = 1e3, s[:len(s)-2]
	case strings.HasSuffix(s, "b"):
		s = s[:len(s)-1]
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || f <= 0 {
		return 0
	}
	v := int64(f * float64(mult))
	if bits {
		v /= 8
	}
	return v
}
