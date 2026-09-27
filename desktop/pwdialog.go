package main

// adminPasswordDialog is the network-admin-password prompt shared by the
// server-rendered settings pages. Every admin-signed action opens it on top of
// the page instead of reading a password field at the bottom of a section.
// The password is used for that one request, cleared on close and never kept.
//
// withAdminPassword(opts, run): opts = {title, who, ok, danger, working};
// run(password) resolves to null on success or an error string, which is shown
// inside the dialog so a mistyped password can be retried. Resolves true on
// success, false when cancelled.
const adminPasswordDialog = `
<style>
  .pwb{position:fixed;inset:0;background:rgba(0,0,0,.62);display:none;align-items:center;justify-content:center;z-index:50;padding:20px}
  .pwb.show{display:flex}
  .pwd{width:100%;max-width:380px;background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:14px;padding:22px;box-shadow:0 18px 60px rgba(0,0,0,.5)}
  .pwd h2{font-size:16px;margin:0 0 4px}
  .pwd .pww{color:var(--muted);font-size:12px;margin:0 0 4px}
  .pwd .pwm{color:#e6b400;font-size:13px;min-height:1em;margin-top:10px;word-break:break-word}
  .pwd .pwa{display:flex;gap:10px;justify-content:flex-end;margin-top:18px}
  .pwd .pwa button{padding:9px 16px}
  .pwd .pwc{background:transparent;color:var(--fg);border:1px solid var(--line)}
  .pwd .pwo{background:var(--accent);color:var(--bg)}
  .pwd .pwo.danger{background:#e5484d;color:#fff}
  .pwd .pwo:disabled{opacity:.6;cursor:progress}
</style>
<div class="pwb" id="pwModal" role="dialog" aria-modal="true" aria-labelledby="pwTitle">
  <div class="pwd">
    <h2 id="pwTitle">Network admin password</h2>
    <p class="pww" id="pwWho"></p>
    <form id="pwForm" autocomplete="off" onsubmit="return false">
      <input type="text" name="username" value="network-admin" autocomplete="username" hidden>
      <label for="pwInput">Network admin password</label>
      <input id="pwInput" type="password" autocomplete="current-password" spellcheck="false">
    </form>
    <div class="pwm" id="pwMsg"></div>
    <div class="pwa">
      <button type="button" class="pwc" id="pwCancel">Cancel</button>
      <button type="button" class="pwo" id="pwOk">Continue</button>
    </div>
  </div>
</div>
<script>
function withAdminPassword(o, run){
  return new Promise((resolve) => {
    const m = document.getElementById('pwModal');
    const inp = document.getElementById('pwInput');
    const msg = document.getElementById('pwMsg');
    const ok = document.getElementById('pwOk');
    const cancel = document.getElementById('pwCancel');
    document.getElementById('pwTitle').textContent = o.title || 'Network admin password';
    document.getElementById('pwWho').textContent = o.who || '';
    ok.textContent = o.ok || 'Continue';
    ok.className = 'pwo' + (o.danger ? ' danger' : '');
    ok.disabled = false;
    inp.value = ''; msg.textContent = '';
    let busy = false;
    function key(e){
      if(e.key === 'Escape' && !busy){ e.preventDefault(); close(false); }
      else if(e.key === 'Enter' && !e.shiftKey){ e.preventDefault(); ok.click(); }
    }
    function close(v){
      m.classList.remove('show');
      ok.onclick = null; cancel.onclick = null; m.onclick = null;
      document.removeEventListener('keydown', key, true);
      inp.value = '';
      resolve(v);
    }
    cancel.onclick = () => { if(!busy) close(false); };
    m.onclick = (e) => { if(e.target === m && !busy) close(false); };
    ok.onclick = async () => {
      if(busy) return;
      const pw = inp.value;
      if(!pw){ msg.textContent = 'Enter the network admin password.'; inp.focus(); return; }
      busy = true; ok.disabled = true; msg.textContent = o.working || 'Working…';
      let err = null;
      try{ err = await run(pw); }catch(e){ err = 'Request failed: ' + e; }
      busy = false; ok.disabled = false;
      if(err){ msg.textContent = err; inp.focus(); inp.select(); return; }
      close(true);
    };
    document.addEventListener('keydown', key, true);
    m.classList.add('show');
    setTimeout(() => inp.focus(), 0);
  });
}
</script>
`
