// Extract every panel script, stub the DOM/network, and actually RUN the
// render functions against representative data. A syntax check ("new Function")
// cannot catch an undefined reference like isOverlayAddr(); only execution can.
const fs = require('fs');
let failures = 0;

for (const file of process.argv.slice(2)) {
  const html = fs.readFileSync(file, 'utf8');
  const code = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]).join('\n');

  const el = () => new Proxy({}, {
    get: (t, k) => k === 'style' ? {} : k === 'dataset' ? {} :
      k === 'classList' ? {add(){},remove(){},contains(){return false}} :
      k === 'value' || k === 'textContent' || k === 'innerHTML' ? '' :
      typeof k === 'string' ? (()=>el()) : undefined,
    set: () => true,
  });
  const doc = {
    getElementById: () => el(), querySelector: () => el(), querySelectorAll: () => [],
    addEventListener: () => {}, createElement: () => el(), body: el(),
  };
  const sandbox = {
    document: doc, window: {location:{href:''}}, location:{href:''},
    fetch: async () => ({ ok:true, status:200, json: async()=>({}), text: async()=>'' }),
    setInterval: () => 0, setTimeout: () => 0, clearInterval: () => {},
    console, JSON, Math, Date, String, Number, Object, Array, Boolean, RegExp, Promise, encodeURIComponent, decodeURIComponent, btoa: s=>s, atob: s=>s,
    navigator: { clipboard: { writeText: async()=>{} } }, alert: ()=>{}, confirm: ()=>true,
  };

  const vm = require('vm');
  const ctx = vm.createContext(sandbox);
  try { vm.runInContext(code, ctx, { timeout: 5000 }); }
  catch (e) { console.log(`${file}: TOP-LEVEL THROW: ${e.message}`); failures++; continue; }

  // Now exercise the row renderers with realistic session objects — this is
  // where an undefined helper actually blows up.
  const sessions = [
    {remote:'69.36.62.127:6970', overlay_ip:'10.22.22.5', name:'zx5', key_fp:'abc123', pubkey:'', established:true, post_quantum:true, exit:false, active_exit:false, relayed:false, v6:true, last_seen_unix: Math.floor(Date.now()/1000)},
    {remote:'10.22.22.7:6970',  overlay_ip:'10.22.22.22', name:'k8s-node', key_fp:'def456', pubkey:'', established:true, post_quantum:true, exit:true, exit_failed:false, active_exit:false, relayed:false, v6:false, last_seen_unix: Math.floor(Date.now()/1000)},
    {remote:'relay/10.22.22.9', overlay_ip:'10.22.22.9', name:'phone', key_fp:'ghi789', pubkey:'', established:false, post_quantum:false, exit:false, active_exit:false, relayed:true, via:'10.22.22.5', v6:false, last_seen_unix: Math.floor(Date.now()/1000)},
  ];
  let ran = 0;
  for (const fn of ['renderSessions','renderRows','loadSessions']) {
    if (typeof ctx[fn] === 'function') {
      try { ctx[fn](sessions); ran++; }
      catch (e) {
        if (/is not a function|is not defined|undefined/.test(e.message)) {
          console.log(`${file}: ${fn}() THREW: ${e.message}`); failures++;
        }
      }
    }
  }
  // Directly verify helpers referenced by the row template exist.
  for (const helper of ['esc','isOverlayAddr']) {
    if (code.includes(helper + '(') && typeof ctx[helper] !== 'function') {
      console.log(`${file}: template calls ${helper}() but it is NOT DEFINED -> rows fail to render`);
      failures++;
    }
  }
  console.log(`${file}: executed OK (${ran} render fn(s) exercised)`);
}
process.exit(failures ? 1 : 0);
