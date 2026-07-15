package main

// features.go adds device approval (admission control), network name/PSK
// rotation, and tracker management to the desktop admin panel — mirroring the
// container admin. All UI is in-page (no browser pop-ups).

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
)

func handleAdminApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PubKey   string `json:"pubkey"`
		Action   string `json:"action"`
		Password string `json:"password"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
	if json.Unmarshal(body, &req) != nil || req.PubKey == "" {
		http.Error(w, "device public key required", http.StatusBadRequest)
		return
	}
	if req.Action != "approve" && req.Action != "deny" {
		req.Action = "approve"
	}
	if !adminKeyAvailable() {
		http.Error(w, "No network admin key exists yet. Create one in Settings.", http.StatusBadRequest)
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
	if pub := adminPublicKeyB64(); pub != "" {
		pushAdminPubKey(pub)
	}
	recBytes, _ := json.Marshal(rec)
	proxyCtl(w, "POST", "/api/approve-signed", recBytes)
}

func handleAdminNetwork(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
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
		http.Error(w, "PSK must start with base64: (use Generate)", http.StatusBadRequest)
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
	proxyCtl(w, "POST", "/api/network-config-signed", recBytes)
}

func handleAdminPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
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
		http.Error(w, "No network admin key exists yet. Create one in Settings.", http.StatusBadRequest)
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
	if pub := adminPublicKeyB64(); pub != "" {
		pushAdminPubKey(pub)
	}
	recBytes, _ := json.Marshal(rec)
	proxyCtl(w, "POST", "/api/policy-signed", recBytes)
}

// defaultDesktopTrackers mirrors the client's built-in list, used when neither
// the running client nor a stored trackers.txt has anything yet.
func defaultDesktopTrackers() []string {
	return []string{
		"udp://tracker.opentrackr.org:1337/announce",
		"udp://tracker.openbittorrent.com:6969/announce",
		"udp://exodus.desync.com:6969/announce",
		"udp://tracker.torrent.eu.org:451/announce",
		"udp://tracker.leechers-paradise.org:6969/announce",
		"udp://tracker.pomeranian.cc:6969/announce",
	}
}

// readTrackersFile loads the stored trackers.txt (one per line), or nil.
func readTrackersFile() []string {
	b, err := os.ReadFile(trackersPath())
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// writeTrackersFile persists the list to trackers.txt so it survives even when
// the client isn't running, and the client picks it up (TRACKERS_FILE) on start.
// One tracker per line, separated by ONE blank line — the canonical format of
// config/trackers.txt, shared by every platform's tracker editor. (Readers skip
// blank lines, so files in either format parse fine.)
func writeTrackersFile(list []string) error {
	return os.WriteFile(trackersPath(), []byte(strings.Join(list, "\n\n")+"\n"), 0o600)
}

func handleAdminTrackers(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
		// Persist to the stored file first so it sticks whether or not the
		// client is currently running, then hand it to the live client too.
		var req struct {
			Trackers []string `json:"trackers"`
		}
		if json.Unmarshal(body, &req) == nil && len(req.Trackers) > 0 {
			_ = writeTrackersFile(req.Trackers)
		}
		_, resp, err := ctlDo("POST", "/api/trackers", body)
		if err != nil {
			// Client not running — the file write above is the source of truth.
			writeJSON(w, map[string]any{"trackers": readTrackersFile()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
		return
	}
	// GET: prefer the live client; fall back to the stored file, then defaults,
	// so the box always autopopulates.
	if _, b, err := ctlDo("GET", "/api/trackers", nil); err == nil {
		var m struct {
			Trackers []string `json:"trackers"`
		}
		if json.Unmarshal(b, &m) == nil && len(m.Trackers) > 0 {
			writeJSON(w, map[string]any{"trackers": m.Trackers})
			return
		}
	}
	list := readTrackersFile()
	if len(list) == 0 {
		list = defaultDesktopTrackers()
	}
	writeJSON(w, map[string]any{"trackers": list})
}

func networkPageHTML() string {
	current := ""
	pqChecked := ""
	if _, b, err := ctlDo("GET", "/api/join-info", nil); err == nil {
		var m struct {
			NetworkName string `json:"network_name"`
		}
		if json.Unmarshal(b, &m) == nil {
			current = m.NetworkName
		}
	}
	if _, b, err := ctlDo("GET", "/api/info", nil); err == nil {
		var m struct {
			PostQuantum bool `json:"post_quantum"`
		}
		if json.Unmarshal(b, &m) == nil && m.PostQuantum {
			pqChecked = "checked"
		}
	}
	return featurePageShell("Network settings", `
  <h1>Security policy</h1>
  <p class="sub">Toggle the hybrid post-quantum layer (ML-KEM-768) for the WHOLE network with the network admin password. Applies live to every device on every platform — no reconnect. Slightly slower; safe to roll out.</p>
  <label style="display:flex;align-items:center;gap:8px;text-transform:none;letter-spacing:0"><input id="pq" type="checkbox" `+pqChecked+` style="width:auto"> Post-quantum encryption (network-wide)</label>
  <label>Network admin password</label>
  <input id="pqpw" type="password">
  <button type="button" class="primary" onclick="applyPolicy()">Apply security policy</button>
  <p id="pmsg" class="msg"></p>
  <hr style="border:0;border-top:1px solid var(--line);margin:26px 0">
  <h1>Network settings</h1>
  <p class="sub">Rotate the network name and PSK — every approved device receives the change and reconnects. Use this if the network is ever compromised. Offline or removed devices will not follow.</p>
  <p class="warn">Changing these briefly disconnects the whole mesh while nodes reconnect.</p>
  <label>New network name</label>
  <input id="netname" type="text" spellcheck="false" value="`+htmlEsc(current)+`">
  <label>New pre-shared key</label>
  <div class="row"><input id="psk" type="text" spellcheck="false" placeholder="base64:…"><button type="button" class="gen" onclick="genPsk()">Generate</button></div>
  <label>Network admin password</label>
  <input id="pw" type="password">
  <button type="button" class="primary" onclick="rotate()">Apply rotation</button>
  <p id="msg" class="msg"></p>
  <p class="sub" style="margin-top:18px"><a href="/settings" style="color:var(--fg)">← Back to Settings</a></p>
`, `
function genPsk(){const b=new Uint8Array(32);crypto.getRandomValues(b);document.getElementById('psk').value='base64:'+btoa(String.fromCharCode.apply(null,b));}
async function applyPolicy(){const msg=document.getElementById('pmsg');msg.textContent='Signing + distributing…';
 const r=await fetch('/api/policy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({post_quantum:document.getElementById('pq').checked,password:document.getElementById('pqpw').value})});
 const t=await r.text();msg.textContent=r.ok?'Security policy applied network-wide.':('Failed: '+t);msg.style.color=r.ok?'#38c172':'#e6b400';document.getElementById('pqpw').value='';}
async function rotate(){const msg=document.getElementById('msg');msg.textContent='Signing + distributing…';
 const r=await fetch('/api/network',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({network_name:document.getElementById('netname').value,psk:document.getElementById('psk').value,password:document.getElementById('pw').value})});
 const t=await r.text();msg.textContent=r.ok?'Rotation sent. Devices reconnect shortly.':('Failed: '+t);msg.style.color=r.ok?'#38c172':'#e6b400';}
`)
}

func trackersPageHTML() string {
	return featurePageShell("Trackers", `
  <h1>Torrent trackers</h1>
  <p class="sub">These help nodes discover each other. One tracker per line, separated by one blank line — edit the box to add or remove them. Changes apply within a minute, no restart.</p>
  <textarea id="trk" spellcheck="false" placeholder="udp://tracker.example.org:6969/announce" style="width:100%;height:220px;background:var(--field);color:var(--fg);border:1px solid var(--line);border-radius:10px;padding:11px 12px;font-family:ui-monospace,Menlo,monospace;font-size:13px;outline:none"></textarea>
  <button type="button" class="primary" onclick="saveT()" style="margin-top:14px">Save changes</button>
  <p id="msg" class="msg"></p>
  <p class="sub" style="margin-top:18px"><a href="/settings" style="color:var(--fg)">← Back to Settings</a></p>
`, `
async function load(){const r=await fetch('/api/trackers');const j=await r.json();document.getElementById('trk').value=(j.trackers||[]).join('\n\n');}
async function saveT(){const msg=document.getElementById('msg');msg.textContent='Saving…';const list=document.getElementById('trk').value.split('\n').map(s=>s.trim()).filter(s=>s.length>0);const r=await fetch('/api/trackers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({trackers:list})});const j=await r.json().catch(()=>({}));if(r.ok){document.getElementById('trk').value=(j.trackers||list).join('\n\n');msg.textContent='Saved.';msg.style.color='#38c172';}else{msg.textContent='Save failed';msg.style.color='#e6b400';}}
load();
`)
}

func featurePageShell(title, body, script string) string {
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>APGO — ` + htmlEsc(title) + `</title>
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
  .tlist{margin:6px 0 12px}.trow{display:flex;align-items:center;gap:8px;padding:8px 10px;border:1px solid var(--line);border-radius:9px;margin-bottom:6px}
  .turl{flex:1;font-size:13px;word-break:break-all}.rm{background:transparent;color:#e06c6c;border:1px solid var(--line);padding:5px 10px}
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
