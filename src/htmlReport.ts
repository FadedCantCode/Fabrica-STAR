import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { ScanResult, Severity } from "./types.js";

const HISTORY_DIR = join(homedir(), ".fabrica-star");
const HISTORY_PATH = join(HISTORY_DIR, "history.json");

const PENALTY: Record<Severity, number> = { critical:30, high:15, medium:5, low:2, info:0 };

export interface ScoreResult {
  score: number;
  grade: "A"|"B"|"C"|"D"|"F";
  label: string;
  color: string;
}

export function calculateScore(result: ScanResult): ScoreResult {
  const pen = result.servers.flatMap(s=>s.findings).reduce((s,f)=>s+PENALTY[f.severity],0);
  const score = Math.max(0, Math.round(100 - pen));
  if (score>=90) return {score, grade:"A", label:"Excellent", color:"#3a7a4a"};
  if (score>=75) return {score, grade:"B", label:"Good",      color:"#6d9e3a"};
  if (score>=60) return {score, grade:"C", label:"Fair",      color:"#9a7a10"};
  if (score>=40) return {score, grade:"D", label:"Poor",      color:"#e8552f"};
  return               {score, grade:"F", label:"Critical",   color:"#6d3ae6"};
}

interface HistEntry { date:string; score:number; grade:string; serverCount:number; critical:number; high:number; }
interface History    { entries: HistEntry[]; }

function loadHistory(): History {
  try {
    const p = JSON.parse(readFileSync(HISTORY_PATH,"utf-8")) as History;
    return Array.isArray(p.entries) ? p : { entries:[] };
  } catch { return { entries:[] }; }
}

export function saveHistoryEntry(result: ScanResult, s: ScoreResult): void {
  const h = loadHistory();
  const all = result.servers.flatMap(sv=>sv.findings);
  h.entries.push({ date:new Date().toISOString(), score:s.score, grade:s.grade,
    serverCount:result.servers.length,
    critical:all.filter(f=>f.severity==="critical").length,
    high:all.filter(f=>f.severity==="high").length });
  h.entries = h.entries.slice(-30);
  try { mkdirSync(HISTORY_DIR,{recursive:true}); writeFileSync(HISTORY_PATH,JSON.stringify(h,null,2),"utf-8"); } catch {}
}

function esc(s:unknown):string {
  return String(s??"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

const SEV_BG:Record<string,string> = {
  critical:"#ede9fd", high:"#fde8e2", medium:"#fef9e3", low:"#e8f5eb", info:"#f0f0f0", clean:"#e8f5eb"
};
const SEV_FG:Record<string,string> = {
  critical:"#6d3ae6", high:"#e8552f", medium:"#9a7a10", low:"#3a7a4a", info:"#888", clean:"#3a7a4a"
};

function donut(items:{label:string;value:number;color:string}[]):string {
  const total = items.reduce((s,d)=>s+d.value,0);
  if(!total) return `<svg width="180" height="180" viewBox="0 0 180 180"><circle cx="90" cy="90" r="60" fill="none" stroke="#e7e2d3" stroke-width="24"/><text x="90" y="95" text-anchor="middle" font-family="Geist Mono,monospace" font-size="12" fill="rgba(24,20,15,0.42)">All clean</text></svg>`;
  const cx=90,cy=90,r=60,sw=24;
  let a=-Math.PI/2;
  const arcs=items.filter(d=>d.value>0).map(d=>{
    const ang=(d.value/total)*2*Math.PI, ea=a+ang;
    const x1=cx+r*Math.cos(a),y1=cy+r*Math.sin(a),x2=cx+r*Math.cos(ea),y2=cy+r*Math.sin(ea);
    const la=ang>Math.PI?1:0;
    a=ea;
    return `<path d="M${x1} ${y1} A${r} ${r} 0 ${la} 1 ${x2} ${y2}" fill="none" stroke="${d.color}" stroke-width="${sw}" stroke-linecap="butt"/>`;
  }).join("");
  return `<svg width="180" height="180" viewBox="0 0 180 180">
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#e7e2d3" stroke-width="${sw}"/>
    ${arcs}
    <text x="${cx}" y="${cy-6}" text-anchor="middle" font-family="Pixelify Sans,monospace" font-size="26" font-weight="700" fill="#18140f">${total}</text>
    <text x="${cx}" y="${cy+14}" text-anchor="middle" font-family="Geist Mono,monospace" font-size="9" letter-spacing="0.06em" fill="rgba(24,20,15,0.42)">FINDINGS</text>
  </svg>`;
}

function bars(servers:ScanResult["servers"]):string {
  const sorted=[...servers].sort((a,b)=>{
    const o=["critical","high","medium","low","info"];
    return o.indexOf(a.riskLevel)-o.indexOf(b.riskLevel);
  });
  const max=Math.max(1,...servers.map(s=>s.findings.length));
  const W=400,bH=26,gap=8,pL=110,pR=16;
  const h=sorted.length*(bH+gap)+20;
  const rows=sorted.map((s,i)=>{
    const y=10+i*(bH+gap);
    const bW=Math.max(6,(s.findings.length/max)*(W-pL-pR));
    const col=SEV_FG[s.riskLevel]??"#888";
    const name=s.server.length>14?s.server.slice(0,12)+"…":s.server;
    return `<text x="${pL-8}" y="${y+bH/2+4}" text-anchor="end" font-family="Geist Mono,monospace" font-size="10" fill="rgba(24,20,15,0.68)">${esc(name)}</text>
    <rect x="${pL}" y="${y}" width="${bW}" height="${bH}" rx="6" fill="${col}" opacity="0.2"/>
    <rect x="${pL}" y="${y}" width="${Math.min(bW,6)}" height="${bH}" rx="3" fill="${col}"/>
    <text x="${pL+bW+6}" y="${y+bH/2+4}" font-family="Geist Mono,monospace" font-size="11" fill="${col}" font-weight="600">${s.findings.length}</text>`;
  }).join("");
  return `<svg width="${W}" height="${h}" viewBox="0 0 ${W} ${h}" style="width:100%">${rows}</svg>`;
}

function trend(history:History):string {
  if(history.entries.length<2) return "";
  const es=history.entries.slice(-12);
  const W=520,H=120,pt=16,pb=28,pl=36,pr=16;
  const pw=W-pl-pr,ph=H-pt-pb;
  const scores=es.map(e=>e.score);
  const mx=100,mn=Math.max(0,Math.min(...scores)-10);
  const pts=es.map((e,i)=>({
    x:pl+(i/(es.length-1))*pw,
    y:pt+(1-(e.score-mn)/(mx-mn))*ph,
    s:e.score, d:e.date.slice(0,10)
  }));
  const line=pts.map(p=>`${p.x},${p.y}`).join(" ");
  const area=`${pl},${pt+ph} ${line} ${pl+pw},${pt+ph}`;
  const dots=pts.map(p=>`<circle cx="${p.x}" cy="${p.y}" r="3.5" fill="#18140f" stroke="#f5f1e6" stroke-width="2"><title>${p.d}: ${p.s}/100</title></circle>`).join("");
  const yg=[0,50,100].map(v=>{
    const y=pt+(1-(v-mn)/(mx-mn))*ph;
    if(y<pt||y>pt+ph) return "";
    return `<line x1="${pl}" y1="${y}" x2="${pl+pw}" y2="${y}" stroke="rgba(24,20,15,0.08)" stroke-width="1"/>
    <text x="${pl-4}" y="${y+4}" text-anchor="end" font-family="Geist Mono,monospace" font-size="8" fill="rgba(24,20,15,0.42)">${v}</text>`;
  }).join("");
  return `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" style="width:100%">
    ${yg}
    <polyline points="${area}" fill="rgba(24,20,15,0.05)" stroke="none"/>
    <polyline points="${line}" fill="none" stroke="#18140f" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
    ${dots}
  </svg>`;
}

export function generateHtmlReport(result: ScanResult): string {
  const scored = calculateScore(result);
  saveHistoryEntry(result, scored);
  const history = loadHistory();

  const all = result.servers.flatMap(s=>s.findings);
  const bySev = {
    critical: all.filter(f=>f.severity==="critical").length,
    high:     all.filter(f=>f.severity==="high").length,
    medium:   all.filter(f=>f.severity==="medium").length,
    low:      all.filter(f=>f.severity==="low").length,
    info:     all.filter(f=>f.severity==="info").length,
  };
  const clean = result.servers.filter(s=>s.findings.length===0).length;
  const compound = result.generalFindings.filter(f=>f.ruleId.startsWith("compound-"));

  const now = new Date().toLocaleString("en-US",{month:"short",day:"numeric",year:"numeric",hour:"2-digit",minute:"2-digit",hour12:false});

  const donutSvg = donut([
    {label:"Critical", value:bySev.critical, color:SEV_FG.critical},
    {label:"High",     value:bySev.high,     color:SEV_FG.high},
    {label:"Medium",   value:bySev.medium,   color:SEV_FG.medium},
    {label:"Low",      value:bySev.low,      color:SEV_FG.low},
    {label:"Clean",    value:clean,           color:SEV_FG.clean},
  ]);

  const trendSvg = trend(history);

  const legendHtml = [
    {label:"Critical", count:bySev.critical, color:SEV_FG.critical},
    {label:"High",     count:bySev.high,     color:SEV_FG.high},
    {label:"Medium",   count:bySev.medium,   color:SEV_FG.medium},
    {label:"Low",      count:bySev.low,      color:SEV_FG.low},
    {label:"Clean",    count:clean,           color:SEV_FG.clean},
  ].filter(l=>l.count>0).map(l=>`
    <div class="legend-item">
      <span class="legend-dot" style="background:${l.color}"></span>
      <span class="legend-label">${l.label}</span>
      <span class="legend-count" style="color:${l.color}">${l.count}</span>
    </div>`).join("");

  const serverCards = result.servers.map(s=>{
    const bg = SEV_BG[s.riskLevel]??"#f0f0f0";
    const fg = SEV_FG[s.riskLevel]??"#888";
    const rows = s.findings.map(f=>`
      <tr class="finding-row">
        <td class="td-rule">${esc(f.ruleId)}</td>
        <td class="td-sev">
          <span class="sev-pill" style="background:${SEV_BG[f.severity]};color:${SEV_FG[f.severity]}">${esc(f.severity)}</span>
        </td>
        <td class="td-msg">${esc(f.message.split("\n")[0])}</td>
      </tr>`).join("");
    const empty = s.findings.length===0
      ? `<tr><td colspan="3" class="td-clean">✔ no issues found</td></tr>`:"";
    return `
    <div class="server-card">
      <div class="server-head" style="background:${bg}22;border-bottom:1.5px solid ${fg}22">
        <span class="sev-pill" style="background:${bg};color:${fg};border:1.5px solid ${fg}44">${esc(s.riskLevel==="info"?"clean":s.riskLevel)}</span>
        <span class="server-name">${esc(s.server)}</span>
        <span class="server-file">${esc(s.sourceFile)}</span>
      </div>
      <table class="finding-table">
        <thead><tr>
          <th class="th">Rule</th>
          <th class="th">Severity</th>
          <th class="th">Finding</th>
        </tr></thead>
        <tbody>${rows}${empty}</tbody>
      </table>
    </div>`;
  }).join("");

  const compoundHtml = compound.length>0 ? `
  <div class="panel" style="margin-bottom:24px">
    <div class="panel-header"><span class="panel-label">⚡ Compound Risk Chains</span></div>
    <div style="padding:16px 20px">
      ${compound.map(f=>`
      <div class="compound-card">
        <div class="compound-rule">${esc(f.ruleId)}</div>
        <div class="compound-msg">${esc(f.message)}</div>
      </div>`).join("")}
    </div>
  </div>` : "";

  return `<!DOCTYPE html>
<html lang="en" style="color-scheme:light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<title>Fabrica-STAR Report — ${esc(now)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Pixelify+Sans:wght@400;700&family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
  :root {
    color-scheme: light;
    --bg:#f5f1e6; --bg-raised:#fbf8f0; --bg-raised-2:#efe9d8;
    --ink:#18140f; --ink-muted:rgba(24,20,15,0.68); --ink-faint:rgba(24,20,15,0.42);
    --border:rgba(24,20,15,0.12); --border-strong:rgba(24,20,15,0.28);
    --radius:12px; --radius-lg:20px; --radius-pill:999px;
    --shadow:0 6px 0 0 #18140f; --shadow-sm:0 4px 0 0 #18140f;
    --font-display:'Pixelify Sans',monospace;
    --font-sans:'Geist',system-ui,sans-serif;
    --font-mono:'Geist Mono','Courier New',monospace;
  }
  *, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
  html { background:var(--bg); }
  body { background:#f5f1e6 !important; color:#18140f !important; font-family:var(--font-sans); font-size:15px; line-height:1.5; min-height:100vh; }

  /* NAV */
  .nav { display:flex; align-items:center; justify-content:space-between; padding:14px 40px; border-bottom:1.5px solid var(--border-strong); background:var(--bg); position:sticky; top:0; z-index:10; }
  .logo { display:flex; align-items:center; gap:10px; text-decoration:none; color:var(--ink); }
  .logo-mark { width:32px; height:32px; background:var(--ink); border-radius:8px; display:flex; align-items:center; justify-content:center; font-family:var(--font-display); font-size:18px; font-weight:700; color:var(--bg); }
  .logo-text { font-family:var(--font-display); font-size:20px; font-weight:700; color:var(--ink); }
  .nav-right { display:flex; align-items:center; gap:12px; }
  .nav-badge { font-family:var(--font-mono); font-size:11px; padding:3px 10px; border-radius:var(--radius-pill); border:1.5px solid var(--border-strong); color:var(--ink-muted); background:var(--bg-raised); }
  .nav-time { font-family:var(--font-mono); font-size:11px; color:var(--ink-faint); }
  .btn-print { font-family:var(--font-sans); font-size:13px; font-weight:500; padding:6px 14px; border-radius:var(--radius-pill); border:1.5px solid var(--border-strong); background:var(--bg-raised-2); color:var(--ink-muted); cursor:pointer; transition:all .18s; }
  .btn-print:hover { border-color:var(--ink); color:var(--ink); }

  /* LAYOUT */
  .main { max-width:1040px; margin:0 auto; padding:48px 40px 80px; }

  /* PANEL */
  .panel { background:var(--bg-raised); border:1.5px solid var(--border-strong); border-radius:var(--radius-lg); box-shadow:var(--shadow); overflow:hidden; }
  .panel-header { display:flex; align-items:center; padding:12px 20px; border-bottom:1.5px solid var(--border); background:var(--bg-raised); }
  .panel-label { font-family:var(--font-mono); font-size:11px; letter-spacing:.06em; text-transform:uppercase; color:var(--ink-faint); }

  /* SCORE HERO */
  .hero-grid { display:grid; grid-template-columns:auto 1fr; gap:32px; align-items:start; margin-bottom:32px; }
  .score-card { background:var(--bg-raised); border:1.5px solid var(--border-strong); border-radius:var(--radius-lg); box-shadow:var(--shadow); padding:28px 36px; text-align:center; min-width:160px; }
  .score-grade { font-family:var(--font-display); font-size:72px; font-weight:700; line-height:1; }
  .score-label { font-size:12px; font-weight:600; font-family:var(--font-mono); letter-spacing:.04em; margin-top:4px; }
  .score-num { font-family:var(--font-mono); font-size:22px; font-weight:700; color:var(--ink); margin-top:10px; }
  .score-denom { font-size:13px; color:var(--ink-faint); }

  .hero-title { font-family:var(--font-display); font-size:28px; font-weight:700; line-height:1.2; margin-bottom:20px; color:var(--ink); }
  .stat-row { display:flex; flex-wrap:wrap; gap:20px; margin-bottom:16px; }
  .stat-box { text-align:center; }
  .stat-num { font-family:var(--font-display); font-size:32px; font-weight:700; }
  .stat-key { font-family:var(--font-mono); font-size:9px; letter-spacing:.08em; text-transform:uppercase; color:var(--ink-faint); margin-top:2px; }
  .hero-desc { font-size:13px; color:var(--ink-muted); line-height:1.6; }

  /* CHARTS GRID */
  .charts-grid { display:grid; grid-template-columns:1fr 1.6fr; gap:20px; margin-bottom:24px; }
  .chart-donut { display:flex; justify-content:center; margin-bottom:16px; }
  .legend-item { display:flex; align-items:center; gap:8px; margin-bottom:6px; }
  .legend-dot { width:8px; height:8px; border-radius:3px; flex-shrink:0; }
  .legend-label { font-size:12px; color:var(--ink-muted); flex:1; }
  .legend-count { font-family:var(--font-mono); font-size:12px; font-weight:600; }

  /* SERVER CARDS */
  .server-card { margin-bottom:12px; border:1.5px solid var(--border-strong); border-radius:var(--radius); overflow:hidden; background:var(--bg); }
  .server-head { display:flex; align-items:center; gap:10px; padding:10px 16px; }
  .server-name { font-size:14px; font-weight:600; color:var(--ink); flex:1; }
  .server-file { font-family:var(--font-mono); font-size:10px; color:var(--ink-faint); }

  /* FINDING TABLE */
  .finding-table { width:100%; border-collapse:collapse; }
  .th { padding:6px 12px; text-align:left; font-family:var(--font-mono); font-size:9px; letter-spacing:.08em; text-transform:uppercase; color:var(--ink-faint); font-weight:400; border-bottom:1.5px solid var(--border); background:var(--bg-raised); }
  .finding-row:hover { background:var(--bg-raised); }
  .td-rule { padding:8px 12px; font-family:var(--font-mono); font-size:10px; color:var(--ink-faint); border-bottom:1px solid var(--border); white-space:nowrap; }
  .td-sev  { padding:8px 12px; border-bottom:1px solid var(--border); white-space:nowrap; }
  .td-msg  { padding:8px 12px; font-size:12px; color:var(--ink-muted); border-bottom:1px solid var(--border); line-height:1.55; }
  .td-clean { padding:12px; font-family:var(--font-mono); font-size:11px; color:var(--ink-faint); text-align:center; }
  .sev-pill { display:inline-block; padding:2px 9px; border-radius:var(--radius-pill); font-family:var(--font-mono); font-size:10px; font-weight:600; letter-spacing:.04em; text-transform:uppercase; }

  /* COMPOUND */
  .compound-card { margin-bottom:10px; border:1.5px solid rgba(109,58,230,0.2); border-radius:10px; padding:14px 16px; background:#ede9fd33; }
  .compound-rule { font-family:var(--font-mono); font-size:10px; letter-spacing:.04em; color:#6d3ae6; margin-bottom:6px; }
  .compound-msg { font-size:12px; color:var(--ink-muted); line-height:1.6; white-space:pre-line; }

  /* SECTION */
  .section { margin-bottom:32px; }
  .section-title { font-family:var(--font-display); font-size:18px; font-weight:700; color:var(--ink); margin-bottom:14px; }

  /* FOOTER */
  .footer { border-top:1.5px solid var(--border); padding-top:24px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; }
  .footer-text { font-family:var(--font-mono); font-size:11px; color:var(--ink-faint); }
  .footer-link { color:var(--ink-muted); text-decoration:none; }
  .footer-link:hover { color:var(--ink); }

  /* EYEBROW */
  .eyebrow { font-family:var(--font-mono); font-size:10px; letter-spacing:.08em; text-transform:uppercase; color:var(--ink-faint); margin-bottom:10px; }

  @media (max-width:700px) {
    .hero-grid { grid-template-columns:1fr; }
    .charts-grid { grid-template-columns:1fr; }
    .main { padding:32px 20px 60px; }
    .nav { padding:14px 20px; }
  }
  @media print { .btn-print { display:none; } body { background:#fff; } }
</style>
</head>
<body>

<nav class="nav">
  <a class="logo" href="https://github.com/FadedCantCode/Fabrica-STAR">
    <div class="logo-mark">✦</div>
    <span class="logo-text">Fabrica-STAR</span>
  </a>
  <div class="nav-right">
    <span class="nav-time">${esc(now)}</span>
    <span class="nav-badge">v0.1.8</span>
    <button class="btn-print" onclick="window.print()">Print / PDF</button>
  </div>
</nav>

<div class="main" style="background:#f5f1e6">

  <!-- HERO -->
  <div class="eyebrow" style="color:rgba(24,20,15,0.42)">Security Report</div>
  <div class="hero-grid" style="background:var(--bg)">
    <div class="score-card">
      <div class="score-grade" style="color:${scored.color}">${scored.grade}</div>
      <div class="score-label" style="color:${scored.color}">${scored.label}</div>
      <div class="score-num">${scored.score}<span class="score-denom">/100</span></div>
    </div>
    <div>
      <h1 class="hero-title" style="color:#18140f">${result.servers.length} server${result.servers.length===1?"":"s"} scanned</h1>
      <div class="stat-row" style="background:var(--bg)">
        ${bySev.critical?`<div class="stat-box"><div class="stat-num" style="color:#6d3ae6">${bySev.critical}</div><div class="stat-key">Critical</div></div>`:""}
        ${bySev.high?`<div class="stat-box"><div class="stat-num" style="color:#e8552f">${bySev.high}</div><div class="stat-key">High</div></div>`:""}
        ${bySev.medium?`<div class="stat-box"><div class="stat-num" style="color:#9a7a10">${bySev.medium}</div><div class="stat-key">Medium</div></div>`:""}
        ${clean?`<div class="stat-box"><div class="stat-num" style="color:#3a7a4a">${clean}</div><div class="stat-key">Clean</div></div>`:""}
      </div>
      <p class="hero-desc" style="color:rgba(24,20,15,0.68)">${all.length===0
        ?"✔ No security issues found. Your MCP configuration looks good."
        :`${all.length} finding${all.length===1?"":"s"} across ${result.servers.filter(s=>s.findings.length>0).length} server${result.servers.filter(s=>s.findings.length>0).length===1?"":"s"}. Fix critical and high issues first.`}</p>
    </div>
  </div>

  <!-- CHARTS -->
  <div class="charts-grid section">
    <div class="panel">
      <div class="panel-header"><span class="panel-label">Severity Distribution</span></div>
      <div style="padding:20px">
        <div class="chart-donut">${donutSvg}</div>
        ${legendHtml}
      </div>
    </div>
    <div class="panel">
      <div class="panel-header"><span class="panel-label">Findings per Server</span></div>
      <div style="padding:20px">
        ${result.servers.length>0 ? bars(result.servers) : `<div style="color:var(--ink-faint);font-size:13px;padding:20px 0">No servers found</div>`}
      </div>
    </div>
  </div>

  <!-- TREND -->
  ${trendSvg?`
  <div class="panel section">
    <div class="panel-header">
      <span class="panel-label">Score Trend</span>
      <span style="margin-left:auto;font-family:var(--font-mono);font-size:10px;color:var(--ink-faint)">Last ${history.entries.length} scans</span>
    </div>
    <div style="padding:20px">${trendSvg}</div>
  </div>`:""}

  <!-- COMPOUND -->
  ${compoundHtml}

  <!-- SERVERS -->
  <div class="section">
    <div class="section-title">Server Details</div>
    ${serverCards||`<div style="color:var(--ink-faint);font-size:13px">No servers found.</div>`}
  </div>

  <!-- FOOTER -->
  <footer class="footer">
    <span class="footer-text">Generated by <strong>Fabrica-STAR v0.1.8</strong> · <a class="footer-link" href="https://github.com/FadedCantCode/Fabrica-STAR">github.com/FadedCantCode/Fabrica-STAR</a></span>
    <span class="footer-text">MIT License · No telemetry</span>
  </footer>

</div>
</body>
</html>`;
}
