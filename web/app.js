"use strict";
/* Nmap Studio frontend. Talks to the C backend over WebSocket. */

const $  = (s, r=document) => r.querySelector(s);
const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));
const esc = s => (s==null?"":String(s)).replace(/[&<>"]/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

/* ---------------- state ---------------- */
const state = {
  hosts: new Map(),      // ip -> host object (current scan)
  scanId: null,
  running: false,
  profiles: [],
  nse: [],
  manualCmd: false,      // user edited the command box directly
};

/* ---------------- websocket ---------------- */
let ws, wsReady = false, backlog = [];
function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen = () => {
    wsReady = true;
    $("#wsdot").classList.add("on");
    $("#wstext").textContent = "connected";
    backlog.forEach(m => ws.send(m)); backlog = [];
    send({cmd:"profiles"});
    send({cmd:"history"});
    // NSE catalog (hundreds of scripts) is loaded lazily the first time the
    // NSE tab is opened — keeps the initial connection light.
  };
  ws.onclose = () => {
    wsReady = false;
    $("#wsdot").classList.remove("on");
    $("#wstext").textContent = "disconnected — retrying";
    setTimeout(connect, 1500);
  };
  ws.onmessage = e => { try { onMsg(JSON.parse(e.data)); } catch(_){} };
}
function send(obj){ const m=JSON.stringify(obj); if(wsReady) ws.send(m); else backlog.push(m); }

/* ---------------- message router ---------------- */
function onMsg(m) {
  switch (m.type) {
    case "host":      onHost(m); break;
    case "progress":  onProgress(m); break;
    case "started":   onStarted(m); break;
    case "done":      onDone(m); break;
    case "log":       onLog(m); break;
    case "history":   renderHistory(m.runs); break;
    case "replay_begin": state.hosts.clear(); renderHosts(); drawTopo(); navTo("hosts"); break;
    case "replay_end":   flashLog("info", `loaded scan #${m.scan} (${state.hosts.size} hosts)`); break;
    case "diff":      renderDiff(m); break;
    case "profiles":  state.profiles=m.profiles; renderProfiles(); break;
    case "nse_begin": state.nse=[]; $("#nseDir").textContent=m.dir?("dir: "+m.dir):"scripts dir not found";
                      $("#nseCat").innerHTML='<option value="">all categories</option>'; break;
    case "nse_batch": state.nse.push(...(m.scripts||[])); break;
    case "nse_end":   renderNse(); flashLog("info", `loaded ${m.count} NSE scripts`); break;
    case "inventory": renderInventory(m.hosts); break;
  }
}

/* ---------------- command builder ---------------- */
function buildArgs() {
  const parts = [];
  $$("#flags input[data-flag]").forEach(cb => { if (cb.checked) parts.push(cb.dataset.flag); });
  const t = $("#timing").value; if (t) parts.push(t);
  const ports = $("#ports").value.trim().replace(/\s+/g,"");
  if (ports) parts.push("-p", ports);
  return parts.join(" ");
}
function refreshCmd() {
  if (state.manualCmd) return;
  const targets = $("#targets").value.trim();
  const args = buildArgs();
  $("#cmdPreview").textContent =
    `nmap -oX - ${args}${args?" ":""}${targets || "<targets>"}`.replace(/\s+/g," ").trim();
}
/* parse the editable command box back into targets+args for execution */
function parseCmdBox() {
  // tokens, honoring quotes
  const raw = $("#cmdPreview").textContent.trim();
  const toks = raw.match(/"[^"]*"|'[^']*'|\S+/g) || [];
  let i = 0;
  if (toks[0] === "nmap") i++;
  const args = [], targets = [];
  for (; i < toks.length; i++) {
    let t = toks[i].replace(/^["']|["']$/g,"");
    if (t === "-oX") { i++; continue; }          // we always add our own -oX -
    if (t === "-") continue;
    if (t.startsWith("-")) {
      args.push(t);
      // options that take a value
      if (/^(-p|-sV|--script|--top-ports|-T|--min-rate|-oN|-oG|--script-args|-D|-S|-e|-g|--source-port)$/.test(t)
          && toks[i+1] && !toks[i+1].startsWith("-")) {
        // only consume a value for the ones that truly need it
        if (/^(-p|--script|--top-ports|--min-rate|--script-args|-D|-S|-e|-g|--source-port)$/.test(t)) {
          args.push(toks[++i].replace(/^["']|["']$/g,""));
        }
      }
    } else {
      targets.push(t);
    }
  }
  return { targets: targets.join(" "), args: args.join(" ") };
}

function renderProfiles() {
  const sel = $("#profile");
  sel.innerHTML = "";
  state.profiles.forEach((p,i) => {
    const o = document.createElement("option");
    o.value = i; o.textContent = p.name; o.title = p.desc;
    sel.appendChild(o);
  });
  // default to "Intense scan" if present
  const idx = state.profiles.findIndex(p => /intense scan$/i.test(p.name));
  if (idx>=0) sel.value = idx;
  applyProfile();
}
function applyProfile() {
  const p = state.profiles[+$("#profile").value];
  if (!p) return;
  state.manualCmd = false;
  // reset flag UI then set from profile args
  $$("#flags input[data-flag]").forEach(cb => cb.checked = false);
  $("#ports").value = ""; $("#timing").value = "";
  const a = p.args.split(/\s+/);
  for (let i=0;i<a.length;i++){
    const tok=a[i];
    if(!tok) continue;
    const cb = $(`#flags input[data-flag="${tok}"]`);
    if (cb) { cb.checked = true; continue; }
    if (/^-T[0-5]$/.test(tok)) { $("#timing").value = tok; continue; }
    if (tok==="-p" && a[i+1]) { $("#ports").value=a[++i]; continue; }
    // leftover flags we don't have a checkbox for -> stash as manual
  }
  // if the profile has flags we can't represent, fall back to showing raw args
  const rep = buildArgs().split(/\s+/).filter(Boolean).sort().join(" ");
  const want = p.args.split(/\s+/).filter(Boolean).sort().join(" ").replace(/\s*-p\s+\S+/,"");
  refreshCmd();
  // if representation lost options, show the real profile command instead
  if (p.args && !flagsCover(p.args)) {
    const targets = $("#targets").value.trim();
    $("#cmdPreview").textContent = `nmap -oX - ${p.args} ${targets||"<targets>"}`.replace(/\s+/g," ").trim();
    state.manualCmd = true;
  }
}
function flagsCover(args){
  // true if every token in args maps to a checkbox/timing/ports we toggled
  const toks = args.split(/\s+/).filter(Boolean);
  for (let i=0;i<toks.length;i++){
    const t=toks[i];
    if ($(`#flags input[data-flag="${t}"]`)) continue;
    if (/^-T[0-5]$/.test(t)) continue;
    if (t==="-p"){ i++; continue; }
    return false;
  }
  return true;
}

/* ---------------- scanning ---------------- */
function startScan() {
  const targets = $("#targets").value.trim();
  if (!targets) { flashLog("error","enter at least one target"); return; }
  // reset current view
  state.hosts.clear(); renderHosts(); drawTopo();
  const name = targets.split(/\s+/)[0] + " · " + (buildArgs()||"default");
  let payload;
  if (state.manualCmd) { payload = parseCmdBox(); }
  else { payload = { targets, args: buildArgs() }; }
  if (!payload.targets) payload.targets = targets;
  send({cmd:"scan", targets:payload.targets, args:payload.args, name});
}
function onStarted(m){
  state.scanId = m.scan; state.running = true;
  $("#scanBtn").disabled = true; $("#stopBtn").disabled = false;
  $("#prog").classList.add("show"); $("#progbar").style.width="2%";
  $("#ptext").textContent = "scanning…";
}
function onProgress(m){
  $("#prog").classList.add("show");
  $("#progbar").style.width = Math.max(2,Math.min(100,m.percent||0)) + "%";
  $("#ptext").textContent = `${(m.percent||0).toFixed(1)}%  ${m.task||""}${m.etc?("  ETC "+m.etc):""}`;
}
function onDone(m){
  state.running = false;
  $("#scanBtn").disabled = false; $("#stopBtn").disabled = true;
  $("#progbar").style.width="100%";
  $("#ptext").textContent = m.ok===false ? "scan failed" :
      `done · ${m.up||0} up / ${m.down||0} down · ${(m.elapsed||0)}s  ${m.summary||""}`;
  setTimeout(()=>{ $("#prog").classList.remove("show"); $("#progbar").style.width="0"; }, 2500);
  send({cmd:"history"});
}

/* ---------------- hosts ---------------- */
function onHost(h){ state.hosts.set(h.ip, h); renderHosts(); drawTopo(); }

function portPill(p){
  const cls = p.state==="open"?"open":(p.state==="closed"?"closed":"filtered");
  return `<span class="pill ${cls}">${esc(p.state)}</span>`;
}
function svcText(p){
  let s = esc(p.service||"");
  const extra = [p.product,p.version,p.extrainfo].filter(Boolean).map(esc).join(" ");
  if (p.tunnel) s = esc(p.tunnel)+"/"+s;
  return s + (extra?` <span class="mut">${extra}</span>`:"");
}
function renderHosts(){
  const q = $("#hostFilter").value.toLowerCase();
  const openOnly = $("#openOnly").checked;
  const list = $("#hostList");
  const hosts = [...state.hosts.values()].sort((a,b)=>cmpIp(a.ip,b.ip));
  $("#cHosts").textContent = hosts.length;
  if (!hosts.length){ list.innerHTML = `<div class="empty">No results yet — run a scan.</div>`; return; }
  let html = "";
  for (const h of hosts){
    let ports = (h.ports||[]);
    if (openOnly) ports = ports.filter(p=>p.state==="open");
    const hay = (h.ip+" "+(h.hostname||"")+" "+(h.os||"")+" "+ports.map(p=>p.port+" "+(p.service||"")).join(" ")).toLowerCase();
    if (q && !hay.includes(q)) continue;
    const openN = (h.ports||[]).filter(p=>p.state==="open").length;
    html += `<div class="host" data-ip="${esc(h.ip)}">
      <div class="hhead" onclick="this.parentNode.classList.toggle('collapsed')">
        <span class="pill ${h.state==='up'?'up':'down'}">${esc(h.state||'?')}</span>
        <span class="hip">${esc(h.ip)}</span>
        ${h.hostname?`<span class="hmeta">${esc(h.hostname)}</span>`:""}
        <span class="spacer"></span>
        ${h.os?`<span class="hmeta">${esc(h.os)}${h.osaccuracy?` (${h.osaccuracy}%)`:""}</span>`:""}
        <span class="hmeta">${openN} open</span>
      </div>
      <div class="body">`;
    if (!ports.length){
      html += `<div class="empty" style="padding:12px">no ${openOnly?"open ":""}ports</div>`;
    } else {
      html += `<table><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version / info</th><th></th></tr></thead><tbody>`;
      for (const p of ports){
        html += `<tr>
          <td class="mono">${p.port}/${esc(p.proto)}</td>
          <td>${portPill(p)}</td>
          <td>${esc(p.service||"")}</td>
          <td>${svcText(p).replace(esc(p.service||""),"")||[p.product,p.version,p.extrainfo].filter(Boolean).map(esc).join(" ")}</td>
          <td><button class="btn" style="padding:2px 8px" onclick='chain(${JSON.stringify(h.ip)},${JSON.stringify(p)})'>⋯</button></td>
        </tr>`;
        if (p.scripts && p.scripts.length){
          for (const sc of p.scripts){
            html += `<tr><td></td><td colspan="4"><div class="scripts"><b>${esc(sc.id)}</b>\n${esc(sc.output)}</div></td></tr>`;
          }
        }
      }
      html += `</tbody></table>`;
    }
    html += `</div></div>`;
  }
  list.innerHTML = html || `<div class="empty">nothing matches the filter</div>`;
}
function cmpIp(a,b){
  const pa=(a||"").split(".").map(Number), pb=(b||"").split(".").map(Number);
  if(pa.length===4&&pb.length===4){ for(let i=0;i<4;i++){ if(pa[i]!==pb[i]) return pa[i]-pb[i]; } return 0; }
  return (a||"").localeCompare(b||"");
}

/* ---------------- tool chaining ---------------- */
function chain(ip, p){
  const port = p.port, svc = (p.service||"").toLowerCase();
  const web = /https?|http-proxy|http-alt/.test(svc) || [80,443,8080,8443,8000].includes(port);
  const tls = /ssl|https/.test(svc) || p.tunnel==="ssl" || [443,8443].includes(port);
  const scheme = tls?"https":"http";
  const url = `${scheme}://${ip}:${port}`;
  const opts = [
    ["Copy host:port", `${ip}:${port}`],
    ["ncat connect", `ncat ${tls?"--ssl ":""}${ip} ${port}`],
  ];
  if (web){
    opts.push(["whatweb", `whatweb ${url}`]);
    opts.push(["nuclei", `nuclei -u ${url}`]);
    opts.push(["ffuf dir", `ffuf -u ${url}/FUZZ -w /usr/share/wordlists/dirb/common.txt`]);
    opts.push(["curl -I", `curl -skI ${url}`]);
  }
  if (p.product) opts.push(["searchsploit", `searchsploit ${p.product} ${p.version||""}`.trim()]);
  opts.push(["nmap -sCV this port", `nmap -sCV -p ${port} ${ip}`]);
  if (svc.includes("ssh")) opts.push(["ssh", `ssh root@${ip} -p ${port}`]);
  if (svc.includes("smb")||port===445) opts.push(["smbclient", `smbclient -L //${ip}/ -N`]);

  const menu = document.createElement("div");
  menu.style.cssText="position:fixed;z-index:9999;background:var(--bg3);border:1px solid var(--line);border-radius:8px;padding:6px;box-shadow:0 8px 30px rgba(0,0,0,.5)";
  menu.innerHTML = `<div class="mut" style="padding:4px 8px;font-size:11px">${esc(ip)}:${port} ${esc(svc)}</div>`;
  opts.forEach(([label,cmd])=>{
    const b=document.createElement("div");
    b.style.cssText="padding:6px 10px;cursor:pointer;border-radius:5px;font-family:var(--mono);font-size:12px";
    b.textContent=label;
    b.title=cmd;
    b.onmouseenter=()=>b.style.background="var(--bg2)";
    b.onmouseleave=()=>b.style.background="";
    b.onclick=()=>{ copy(cmd); flashLog("info","copied: "+cmd); document.body.removeChild(menu); };
    menu.appendChild(b);
  });
  const ev = window.event;
  menu.style.left = Math.min(ev.clientX, innerWidth-280)+"px";
  menu.style.top  = Math.min(ev.clientY, innerHeight-opts.length*34-40)+"px";
  document.body.appendChild(menu);
  const close=(e)=>{ if(!menu.contains(e.target)){ if(menu.parentNode)document.body.removeChild(menu); document.removeEventListener("mousedown",close);} };
  setTimeout(()=>document.addEventListener("mousedown",close),0);
}
window.chain = chain;

/* ---------------- console / log ---------------- */
function onLog(m){ flashLog(m.level||"info", m.msg||""); }
function flashLog(level, msg){
  const c=$("#console");
  const div=document.createElement("div");
  div.className="line "+(level||"info");
  div.textContent = (level==="cmd"?"$ ":"")+msg;
  c.appendChild(div);
  while(c.children.length>400) c.removeChild(c.firstChild);
  c.scrollTop=c.scrollHeight;
}

/* ---------------- history ---------------- */
function fmtWhen(ts){ if(!ts) return ""; const d=new Date(ts*1000); return d.toLocaleString(); }
function renderHistory(runs){
  const tb=$("#histBody"); tb.innerHTML="";
  const dA=$("#diffA"), dB=$("#diffB"); dA.innerHTML=""; dB.innerHTML="";
  (runs||[]).forEach(r=>{
    const tr=document.createElement("tr");
    tr.style.cursor="pointer";
    tr.innerHTML=`<td class="mono">${r.id}</td><td>${esc(r.name)}</td><td class="mono">${esc(r.targets)}</td>
      <td>${r.up}</td><td>${r.down}</td><td>${r.elapsed?r.elapsed+"s":""}</td>
      <td><span class="pill ${r.status==='done'?'open':(r.status==='running'?'filtered':'closed')}">${esc(r.status)}</span></td>
      <td class="mut">${fmtWhen(r.started)}</td>`;
    tr.onclick=()=>send({cmd:"load",scan:r.id});
    tb.appendChild(tr);
    [dA,dB].forEach(sel=>{ const o=document.createElement("option"); o.value=r.id;
      o.textContent=`#${r.id} ${r.name}`; sel.appendChild(o); });
  });
  if (dA.options.length>1) dA.selectedIndex=1;
  if (dB.options.length>0) dB.selectedIndex=0;
}

/* ---------------- diff ---------------- */
function renderDiff(m){
  const rowP = r=>`<div class="nse-item"><span class="mono">${esc(r.ip)}:${r.port}/${esc(r.proto)}</span>
     ${r.service?` <span class="mut">${esc(r.service)} ${esc(r.version||"")}</span>`:""}</div>`;
  const rowC = r=>`<div class="nse-item"><span class="mono">${esc(r.ip)}:${r.port}</span>
     <span class="mut"> ${esc(r.from||"")} ${esc(r.fromver||"")} → ${esc(r.to||"")} ${esc(r.tover||"")}</span></div>`;
  $("#diffAdded").innerHTML   = (m.added||[]).length ? m.added.map(rowP).join("")   : `<div class="empty">none</div>`;
  $("#diffRemoved").innerHTML = (m.removed||[]).length ? m.removed.map(rowP).join("") : `<div class="empty">none</div>`;
  $("#diffChanged").innerHTML = (m.changed||[]).length ? m.changed.map(rowC).join("") : `<div class="empty">none</div>`;
}

/* ---------------- NSE ---------------- */
function renderNse(){
  const q=$("#nseFilter").value.toLowerCase();
  const cat=$("#nseCat").value;
  // populate category dropdown once
  if ($("#nseCat").options.length<=1 && state.nse.length){
    const cats=new Set(); state.nse.forEach(s=>(s.categories||[]).forEach(c=>cats.add(c)));
    [...cats].sort().forEach(c=>{ const o=document.createElement("option"); o.value=c; o.textContent=c; $("#nseCat").appendChild(o); });
  }
  const list=$("#nseList");
  const items = state.nse.filter(s=>{
    if (cat && !(s.categories||[]).includes(cat)) return false;
    if (q && !(s.id.toLowerCase().includes(q) || (s.desc||"").toLowerCase().includes(q))) return false;
    return true;
  }).slice(0,600);
  if (!state.nse.length){ list.innerHTML=`<div class="empty">No NSE scripts found. Pass --scripts DIR if nmap is installed elsewhere.</div>`; return; }
  list.innerHTML = items.map(s=>`
    <div class="nse-item">
      <span class="id" onclick='addScript(${JSON.stringify(s.id)})' title="click to add --script">${esc(s.id)}</span>
      <span class="cats">${(s.categories||[]).map(c=>`<span class="cat">${esc(c)}</span>`).join("")}</span>
      <div class="mut" style="margin-top:3px">${esc(s.desc||"")}</div>
    </div>`).join("") || `<div class="empty">no scripts match</div>`;
}
function addScript(id){
  // append --script=id to the command box
  state.manualCmd = true;
  const box=$("#cmdPreview");
  let txt=box.textContent;
  const m=txt.match(/--script[= ]([^\s]+)/);
  if (m){ txt = txt.replace(/--script[= ][^\s]+/, `--script=${m[1]},${id}`); }
  else {
    const targets=$("#targets").value.trim();
    txt = txt.replace(targets,"").trim()+` --script=${id} ${targets}`;
  }
  box.textContent = txt.replace(/\s+/g," ").trim();
  flashLog("info","added script "+id);
  navTo("hosts");
}
window.addScript = addScript;

/* ---------------- inventory ---------------- */
function renderInventory(hosts){
  const tb=$("#invBody"); tb.innerHTML="";
  (hosts||[]).sort((a,b)=>cmpIp(a.ip,b.ip)).forEach(h=>{
    const tr=document.createElement("tr");
    tr.innerHTML=`<td class="mono">${esc(h.ip)}</td><td>${esc(h.hostname||"")}</td>
      <td>${esc(h.os||"")}</td><td>${h.seen}</td><td class="mono">#${h.lastscan}</td>`;
    tr.style.cursor="pointer"; tr.onclick=()=>$("#targets").value=h.ip;
    tb.appendChild(tr);
  });
  if (!hosts || !hosts.length) tb.innerHTML=`<tr><td colspan="5" class="empty">no hosts stored yet</td></tr>`;
}

/* ---------------- topology (canvas force graph) ---------------- */
const topo = { nodes:[], edges:[], cam:{x:0,y:0,z:1}, drag:null, raf:null };
function drawTopo(){
  // rebuild graph from current hosts
  const cx=0, cy=0;
  const nodes=[{id:"__scanner__",label:"scanner",ip:"you",open:0,x:cx,y:cy,fx:cx,fy:cy,scanner:true}];
  const edges=[];
  const keep=new Map(); topo.nodes.forEach(n=>keep.set(n.id,n));
  [...state.hosts.values()].forEach(h=>{
    if (h.state && h.state!=="up" && !(h.ports&&h.ports.length)) return;
    const open=(h.ports||[]).filter(p=>p.state==="open").length;
    const prev=keep.get(h.ip);
    const n={id:h.ip,label:h.ip,ip:h.ip,hostname:h.hostname,os:h.os,open,
      x:prev?prev.x:cx+(Math.random()-.5)*300, y:prev?prev.y:cy+(Math.random()-.5)*300, vx:0,vy:0};
    nodes.push(n);
    // edge via last traceroute hop if present else direct to scanner
    edges.push({a:"__scanner__", b:h.ip, hops:(h.hops||[]).length});
  });
  topo.nodes=nodes; topo.edges=edges;
  if (!topo.raf) simulate();
}
function simulate(){
  const cv=$("#topo"); if(!cv) return;
  const ctx=cv.getContext("2d");
  function step(){
    const W=cv.width=cv.clientWidth*devicePixelRatio, H=cv.height=cv.clientHeight*devicePixelRatio;
    // physics
    const N=topo.nodes;
    for(let i=0;i<N.length;i++){
      const a=N[i]; if(a.scanner) continue;
      a.vx=(a.vx||0)*0.85; a.vy=(a.vy||0)*0.85;
      for(let j=0;j<N.length;j++){ if(i===j) continue;
        const b=N[j]; let dx=a.x-b.x, dy=a.y-b.y; let d2=dx*dx+dy*dy+0.01; let d=Math.sqrt(d2);
        const rep=4000/d2; a.vx+=dx/d*rep; a.vy+=dy/d*rep;
      }
    }
    topo.edges.forEach(e=>{
      const a=topo.nodes.find(n=>n.id===e.a), b=topo.nodes.find(n=>n.id===e.b);
      if(!a||!b) return;
      const dx=b.x-a.x, dy=b.y-a.y, d=Math.sqrt(dx*dx+dy*dy)+.01;
      const target=140+e.hops*30, f=(d-target)*0.01;
      if(!b.scanner){ b.vx-=dx/d*f; b.vy-=dy/d*f; }
      if(!a.scanner){ a.vx+=dx/d*f; a.vy+=dy/d*f; }
    });
    N.forEach(n=>{ if(n.scanner){n.x=0;n.y=0;return;} if(topo.drag&&topo.drag.node===n)return;
      n.x+=n.vx||0; n.y+=n.vy||0; });

    // draw
    ctx.setTransform(1,0,0,1,0,0);
    ctx.clearRect(0,0,W,H);
    ctx.save();
    ctx.translate(W/2+topo.cam.x, H/2+topo.cam.y); ctx.scale(topo.cam.z,topo.cam.z);
    // edges
    ctx.strokeStyle="rgba(88,166,255,.25)"; ctx.lineWidth=1;
    topo.edges.forEach(e=>{
      const a=topo.nodes.find(n=>n.id===e.a), b=topo.nodes.find(n=>n.id===e.b);
      if(!a||!b) return;
      ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke();
    });
    // nodes
    N.forEach(n=>{
      const r = n.scanner?14:(8+Math.min(22,n.open*2));
      const color = n.scanner?"#58a6ff":(n.open>0?"#3fb950":"#8b949e");
      ctx.beginPath(); ctx.arc(n.x,n.y,r,0,7); ctx.fillStyle=color; ctx.globalAlpha=.9; ctx.fill();
      ctx.globalAlpha=1; ctx.lineWidth=2; ctx.strokeStyle=n.scanner?"#1f6feb":"#0d1117"; ctx.stroke();
      ctx.fillStyle="#e6edf3"; ctx.font=`${12}px sans-serif`; ctx.textAlign="center";
      ctx.fillText(n.label, n.x, n.y+r+13);
      if(n.open>0){ ctx.fillStyle="#fff"; ctx.font="bold 10px sans-serif"; ctx.fillText(n.open, n.x, n.y+3); }
    });
    ctx.restore();
    topo.raf=requestAnimationFrame(step);
  }
  step();
}
function topoSetup(){
  const cv=$("#topo");
  cv.addEventListener("mousedown",e=>{
    const p=screenToWorld(e); const n=pickNode(p);
    if(n&&!n.scanner) topo.drag={node:n}; else topo.drag={pan:true,sx:e.clientX,sy:e.clientY,cx:topo.cam.x,cy:topo.cam.y};
  });
  addEventListener("mousemove",e=>{
    if(!topo.drag) return;
    if(topo.drag.node){ const p=screenToWorld(e); topo.drag.node.x=p.x; topo.drag.node.y=p.y; topo.drag.node.vx=0; topo.drag.node.vy=0; }
    else if(topo.drag.pan){ topo.cam.x=topo.drag.cx+(e.clientX-topo.drag.sx); topo.cam.y=topo.drag.cy+(e.clientY-topo.drag.sy); }
  });
  addEventListener("mouseup",()=>topo.drag=null);
  cv.addEventListener("wheel",e=>{ e.preventDefault(); topo.cam.z*=e.deltaY<0?1.1:0.9; topo.cam.z=Math.max(.2,Math.min(4,topo.cam.z)); },{passive:false});
}
function screenToWorld(e){
  const cv=$("#topo"), r=cv.getBoundingClientRect();
  const x=(e.clientX-r.left)*devicePixelRatio, y=(e.clientY-r.top)*devicePixelRatio;
  return { x:(x-cv.width/2-topo.cam.x)/topo.cam.z, y:(y-cv.height/2-topo.cam.y)/topo.cam.z };
}
function pickNode(p){
  for(const n of topo.nodes){ const r=n.scanner?14:(8+Math.min(22,n.open*2));
    if((p.x-n.x)**2+(p.y-n.y)**2 < (r+6)**2) return n; }
  return null;
}

/* ---------------- exports ---------------- */
function download(name, mime, data){
  const b=new Blob([data],{type:mime}), u=URL.createObjectURL(b);
  const a=document.createElement("a"); a.href=u; a.download=name; a.click(); URL.revokeObjectURL(u);
}
function exportJson(){ download("scan.json","application/json",JSON.stringify([...state.hosts.values()],null,2)); }
function exportCsv(){
  let rows=[["ip","hostname","state","os","port","proto","portstate","service","product","version"]];
  state.hosts.forEach(h=>(h.ports||[]).forEach(p=>rows.push(
    [h.ip,h.hostname||"",h.state||"",h.os||"",p.port,p.proto,p.state,p.service||"",p.product||"",p.version||""])));
  download("scan.csv","text/csv",rows.map(r=>r.map(c=>`"${String(c).replace(/"/g,'""')}"`).join(",")).join("\n"));
}
function exportHtml(){
  let h=`<!doctype html><meta charset=utf-8><title>Nmap Studio report</title>
  <style>body{font:14px sans-serif;margin:24px;color:#111}h2{margin:20px 0 6px}
  table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:4px 8px;text-align:left;font-size:13px}
  .open{color:#1a7f37;font-weight:600}.closed{color:#b42318}</style>
  <h1>Nmap Studio report</h1><p>Generated ${new Date().toLocaleString()} · ${state.hosts.size} hosts</p>`;
  [...state.hosts.values()].sort((a,b)=>cmpIp(a.ip,b.ip)).forEach(host=>{
    h+=`<h2>${esc(host.ip)} ${host.hostname?("("+esc(host.hostname)+")"):""} — ${esc(host.state||"")}${host.os?(" · "+esc(host.os)):""}</h2>`;
    h+=`<table><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>`;
    (host.ports||[]).forEach(p=>h+=`<tr><td>${p.port}/${esc(p.proto)}</td>
      <td class="${p.state==='open'?'open':'closed'}">${esc(p.state)}</td>
      <td>${esc(p.service||"")}</td><td>${esc([p.product,p.version,p.extrainfo].filter(Boolean).join(" "))}</td></tr>`);
    h+=`</table>`;
  });
  download("nmap-report.html","text/html",h);
}
function copy(t){ navigator.clipboard?.writeText(t).catch(()=>{}); }

/* ---------------- nav ---------------- */
let nseLoaded = false;
function navTo(v){
  $$("#nav a").forEach(a=>a.classList.toggle("active",a.dataset.view===v));
  $$(".view").forEach(el=>el.classList.toggle("active", el.id==="view-"+v));
  if (v==="inventory") send({cmd:"inventory"});
  if (v==="history") send({cmd:"history"});
  if (v==="nse" && !nseLoaded) { nseLoaded = true; send({cmd:"nse"}); }
}

/* ---------------- wire up ---------------- */
function init(){
  connect();
  topoSetup();
  $$("#nav a").forEach(a=>a.onclick=()=>navTo(a.dataset.view));
  $("#scanBtn").onclick=startScan;
  $("#stopBtn").onclick=()=>send({cmd:"stop"});
  $("#targets").addEventListener("input",refreshCmd);
  $("#targets").addEventListener("keydown",e=>{ if(e.key==="Enter"&&!state.running) startScan(); });
  $("#profile").onchange=applyProfile;
  $$("#flags input, #timing, #ports").forEach(el=>el.addEventListener("input",()=>{state.manualCmd=false;refreshCmd();}));
  $("#cmdPreview").addEventListener("input",()=>{state.manualCmd=true;});
  $("#copyCmd").onclick=()=>{ copy($("#cmdPreview").textContent); flashLog("info","command copied"); };
  $("#hostFilter").addEventListener("input",renderHosts);
  $("#openOnly").addEventListener("change",renderHosts);
  $("#expJson").onclick=exportJson; $("#expCsv").onclick=exportCsv; $("#expHtml").onclick=exportHtml;
  $("#refreshHist").onclick=()=>send({cmd:"history"});
  $("#refreshInv").onclick=()=>send({cmd:"inventory"});
  $("#runDiff").onclick=()=>{ const a=+$("#diffA").value,b=+$("#diffB").value; if(a&&b) send({cmd:"diff",a,b}); };
  $("#nseFilter").addEventListener("input",renderNse);
  $("#nseCat").addEventListener("change",renderNse);
  refreshCmd();
}
document.addEventListener("DOMContentLoaded",init);
