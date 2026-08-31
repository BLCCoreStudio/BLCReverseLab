from __future__ import annotations

import html
import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .analyst import ask_report
from .explorer import build_analysis_graph
from .query import search_report
from .server import WorkspaceStore


def render_studio_app(title: str = "BLCReverseLab Studio") -> str:
    safe_title = html.escape(title, quote=True)
    template = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{color-scheme:dark;--bg:#05070b;--panel:#0b1018;--panel2:#101824;--line:#263448;--muted:#8391a5;--text:#f2f6fb;--blue:#8bc2ff;--green:#8ce0bd;--purple:#c5a7ff;--gold:#f4ca7d;--danger:#ff9c9c}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% -5%,#152a44 0,#080c13 34%,var(--bg) 72%);font-family:Inter,ui-sans-serif,system-ui;color:var(--text)}
header{position:sticky;top:0;z-index:5;background:#070b12e8;border-bottom:1px solid var(--line);backdrop-filter:blur(18px)}nav{max-width:1680px;margin:auto;padding:14px 22px;display:flex;justify-content:space-between;align-items:center;gap:16px}.brand{font-weight:750}.brand small{font-weight:500;color:var(--muted);margin-left:8px}.badge{border:1px solid #34506e;background:#0e1925;padding:6px 10px;border-radius:999px;color:#bfdcff;font-size:12px}
main{max-width:1680px;margin:auto;padding:18px 22px 60px}.shell{display:grid;grid-template-columns:300px minmax(0,1fr);gap:14px}.panel{border:1px solid var(--line);background:linear-gradient(180deg,var(--panel2),var(--panel));border-radius:16px;box-shadow:0 18px 60px #0006}.side{padding:12px;height:calc(100vh - 92px);position:sticky;top:76px;overflow:auto}.main{padding:16px;min-height:78vh}
input,button{font:inherit}input{width:100%;background:#070b12;border:1px solid #2b3b50;color:var(--text);border-radius:10px;padding:10px 11px;outline:none}input:focus{border-color:#527aa8;box-shadow:0 0 0 3px #31577c33}button{cursor:pointer;border:1px solid #31445c;background:#111b28;color:var(--text);padding:9px 12px;border-radius:10px}button:hover{border-color:#5a7ea7}.analysis{width:100%;text-align:left;margin:5px 0}.analysis.active{background:#1a2b40;border-color:#6590be}.analysis strong{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.analysis small{display:block;margin-top:3px;color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));gap:9px;margin:12px 0}.metric{padding:12px;border:1px solid #233246;background:#080e16;border-radius:12px}.metric span{display:block;font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}.metric strong{display:block;margin-top:5px;font-size:19px}.section{margin-top:16px;border-top:1px solid var(--line);padding-top:14px}.section h3{font-size:15px;margin:0 0 9px}.toolbar{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px}.muted{color:var(--muted)}code{color:#c4deff}.answer{margin-top:10px;padding:13px;border:1px solid #2c425c;background:#09131f;border-radius:12px;line-height:1.5}.support{display:grid;gap:6px;margin-top:8px}.support-item{padding:8px 10px;background:#080e16;border:1px solid #202d3f;border-radius:9px;font-size:12px}.support-item b{color:var(--blue)}
.tabs{display:flex;gap:7px;flex-wrap:wrap;margin:12px 0}.tabs button.active{background:#1b3049;border-color:#6795c4}.view{display:none}.view.active{display:block}.graph-wrap{border:1px solid #223147;background:#060a10;border-radius:13px;overflow:auto;min-height:480px}.graph-wrap svg{min-width:1100px;display:block}.legend{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0}.legend span{font-size:11px;border:1px solid #2c3b4e;border-radius:999px;padding:4px 7px}.table{width:100%;border-collapse:collapse;font-size:12px}.table th,.table td{text-align:left;padding:8px;border-bottom:1px solid #1c2939;vertical-align:top}.table th{color:var(--muted)}pre{background:#070b11;border:1px solid #1e2b3c;border-radius:10px;padding:10px;white-space:pre-wrap;word-break:break-word;max-height:420px;overflow:auto}
@media(max-width:900px){.shell{grid-template-columns:1fr}.side{position:static;height:auto}.graph-wrap{min-height:360px}}
</style></head>
<body><header><nav><div class="brand">BLCReverseLab <small>Investigation Studio</small></div><div class="badge" id="health">connecting…</div></nav></header>
<main><div class="shell"><aside class="panel side"><input id="filter" placeholder="Filter analyses"><div id="analyses"></div></aside><section class="panel main"><div id="empty"><h2>Investigation Studio</h2><p class="muted">Select a saved analysis. Studio is local and read-only.</p></div><div id="workspace" hidden></div></section></div></main>
<script>
const S={workspace:null,current:null,analysis:null,graph:null};
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path){const r=await fetch(path,{cache:'no-store'});const data=await r.json().catch(()=>({error:r.statusText}));if(!r.ok)throw new Error(data.error||r.statusText);return data}
function metric(k,v){return `<div class="metric"><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`}
function list(){const q=document.getElementById('filter').value.toLowerCase(),box=document.getElementById('analyses');box.innerHTML='';for(const a of S.workspace.analyses){const hay=`${a.target} ${a.sha256} ${a.file_type||''}`.toLowerCase();if(!hay.includes(q))continue;const b=document.createElement('button');b.className='analysis'+(S.current===a.sha256?' active':'');b.disabled=!a.available;b.innerHTML=`<strong>${esc((a.target||'').split('/').pop()||a.sha256)}</strong><small>${esc(a.file_type||'unknown')} · ${esc(a.sha256.slice(0,10))}</small>`;b.onclick=()=>select(a.sha256);box.appendChild(b)}}
async function select(sha){S.current=sha;list();S.analysis=await api('/api/analysis/'+encodeURIComponent(sha));S.graph=await api('/api/graph?sha='+encodeURIComponent(sha));document.getElementById('empty').hidden=true;const w=document.getElementById('workspace');w.hidden=false;const f=S.analysis.facts||{},g=f.ghidra||{},x=f.jni_crossrefs||{},r=f.recovery||{},p=f.protection||{};w.innerHTML=`<h2>${esc((S.analysis.target||'').split('/').pop()||sha)}</h2><p class="muted"><code>${esc(sha)}</code></p><div class="grid">${metric('Artifact',S.analysis.file_type||'unknown')}${metric('Evidence',(S.analysis.evidence||[]).length)}${metric('Graph nodes',S.graph.stats?.node_count||0)}${metric('Native funcs',g.function_count||0)}${metric('JNI links',x.matched_declaration_count||0)}${metric('Protection',p.level||'none')}${metric('Obfuscation',r.obfuscation_score||0)}</div><div class="section"><h3>Evidence Analyst</h3><div class="toolbar"><input id="askq" placeholder="Where is inventory handled? Which JNI bridge reaches native code?"><button id="askbtn">Ask</button></div><div id="answer" class="muted">Answers are grounded only in this saved analysis.</div></div><div class="section"><div class="tabs"><button class="active" data-tab="graph">Cross-layer graph</button><button data-tab="search">Universal search</button><button data-tab="raw">Raw facts</button></div><div id="tab-graph" class="view active"><div class="legend"><span>managed</span><span>JNI</span><span>native</span><span>network</span><span>recovery</span><span>evidence</span></div><div id="graph" class="graph-wrap"></div></div><div id="tab-search" class="view"><div class="toolbar"><input id="searchq" placeholder="Search classes, functions, endpoints, evidence"><button id="searchbtn">Search</button></div><div id="searchout"></div></div><div id="tab-raw" class="view"><pre>${esc(JSON.stringify(f,null,2))}</pre></div></div>`;document.getElementById('askbtn').onclick=ask;document.getElementById('askq').addEventListener('keydown',e=>{if(e.key==='Enter')ask()});document.getElementById('searchbtn').onclick=search;document.getElementById('searchq').addEventListener('keydown',e=>{if(e.key==='Enter')search()});for(const b of w.querySelectorAll('[data-tab]'))b.onclick=()=>tab(b.dataset.tab);drawGraph(S.graph)}
function tab(name){for(const b of document.querySelectorAll('[data-tab]'))b.classList.toggle('active',b.dataset.tab===name);for(const v of document.querySelectorAll('.view'))v.classList.toggle('active',v.id==='tab-'+name)}
async function ask(){const q=document.getElementById('askq').value.trim();if(!q)return;const out=document.getElementById('answer');out.textContent='Analyzing evidence…';try{const a=await api('/api/ask?sha='+encodeURIComponent(S.current)+'&q='+encodeURIComponent(q));const supports=(a.support||[]).slice(0,8).map(s=>`<div class="support-item"><b>${esc(s.layer)}</b> · ${esc(s.label)} · score ${esc(s.score)}</div>`).join('');out.className='answer';out.innerHTML=`<strong>${esc(a.status)}</strong> · confidence ${esc(a.confidence)}<p>${esc(a.answer)}</p><div class="support">${supports}</div><p class="muted">${esc(a.caveat||'')}</p>`}catch(e){out.className='answer';out.innerHTML=`<span style="color:var(--danger)">${esc(e.message)}</span>`}}
async function search(){const q=document.getElementById('searchq').value.trim();if(!q)return;const d=await api('/api/search?sha='+encodeURIComponent(S.current)+'&q='+encodeURIComponent(q)+'&limit=100');const rows=d.results||[];document.getElementById('searchout').innerHTML=rows.length?`<table class="table"><thead><tr><th>Kind</th><th>Match</th><th>Score</th></tr></thead><tbody>${rows.map(i=>`<tr><td>${esc(i.kind)}</td><td>${esc(i.label)}</td><td>${esc(i.score)}</td></tr>`).join('')}</tbody></table>`:'<p class="muted">No matches.</p>'}
function drawGraph(data){const box=document.getElementById('graph');const order=['managed','jni','native','network','recovery','evidence','other'];const nodes=(data.nodes||[]).slice(0,220),allowed=new Set(nodes.map(n=>n.id)),groups={};for(const l of order)groups[l]=[];for(const n of nodes)(groups[n.layer]||groups.other).push(n);const used=order.filter(l=>groups[l].length),W=Math.max(1100,used.length*210),H=Math.max(500,Math.max(...used.map(l=>groups[l].length),1)*58+90),pos={};used.forEach((layer,xi)=>groups[layer].forEach((n,yi)=>pos[n.id]={x:105+xi*(W-210)/Math.max(1,used.length-1),y:75+yi*58,layer}));const color={managed:'#8bc2ff',jni:'#c5a7ff',native:'#8ce0bd',network:'#f4ca7d',recovery:'#ffb6d4',evidence:'#aab5c5',other:'#8895a7'};const edges=(data.edges||[]).filter(e=>allowed.has(e.source)&&allowed.has(e.target)).slice(0,500);let svg=`<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}">`;for(const e of edges){const a=pos[e.source],b=pos[e.target];if(!a||!b)continue;svg+=`<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="#344357" stroke-width="1" opacity=".72"><title>${esc(e.relation)}</title></line>`}for(const layer of used){for(const n of groups[layer]){const p=pos[n.id],label=String(n.label||n.id);svg+=`<g><circle cx="${p.x}" cy="${p.y}" r="7" fill="${color[layer]||color.other}"/><text x="${p.x+12}" y="${p.y+4}" fill="#dce7f3" font-size="11">${esc(label.length>28?label.slice(0,27)+'…':label)}</text><title>${esc(label)} · ${esc(layer)} · ${esc(n.kind)}</title></g>`}}svg+='</svg>';box.innerHTML=svg}
async function boot(){try{const h=await api('/api/health');document.getElementById('health').textContent=`${h.mode} · localhost`;S.workspace=await api('/api/workspace');document.title=S.workspace.name+' · ReverseLab Studio';list();const a=[...S.workspace.analyses].reverse().find(x=>x.available);if(a)await select(a.sha256)}catch(e){document.getElementById('health').textContent='error';document.getElementById('empty').innerHTML=`<h2>Studio error</h2><pre>${esc(e.message)}</pre>`}}
document.getElementById('filter').addEventListener('input',list);boot();
</script></body></html>'''
    return template.replace("__TITLE__", safe_title)


class _StudioHandler(BaseHTTPRequestHandler):
    store: WorkspaceStore

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return

    def _headers(self, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:",
        )
        self.end_headers()

    def _json(self, payload: Any, status: int = 200) -> None:
        self._headers("application/json; charset=utf-8", status)
        self.wfile.write(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8"))

    def _html(self, payload: str, status: int = 200) -> None:
        self._headers("text/html; charset=utf-8", status)
        self.wfile.write(payload.encode("utf-8"))

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/":
                self._html(render_studio_app(self.store.workspace().get("name", "BLCReverseLab Studio")))
                return
            if parsed.path == "/api/health":
                self._json({"status": "ok", "mode": "read-only", "surface": "studio"})
                return
            if parsed.path == "/api/workspace":
                self._json(self.store.snapshot())
                return
            if parsed.path.startswith("/api/analysis/"):
                sha = unquote(parsed.path.removeprefix("/api/analysis/"))
                self._json(self.store.load_analysis(sha))
                return
            if parsed.path in {"/api/ask", "/api/graph", "/api/search"}:
                params = parse_qs(parsed.query)
                sha = (params.get("sha") or [""])[0]
                if not sha:
                    self._json({"error": "sha is required"}, 400)
                    return
                report = self.store.load_analysis(sha)
                if parsed.path == "/api/graph":
                    self._json(build_analysis_graph(report))
                    return
                query = (params.get("q") or [""])[0].strip()
                if not query:
                    self._json({"error": "q is required"}, 400)
                    return
                if parsed.path == "/api/ask":
                    self._json(ask_report(report, query, limit=8))
                else:
                    limit = max(1, min(int((params.get("limit") or ["100"])[0]), 500))
                    self._json(search_report(report, query, limit=limit))
                return
            self._json({"error": "not found"}, 404)
        except KeyError:
            self._json({"error": "analysis not found in workspace"}, 404)
        except FileNotFoundError as exc:
            self._json({"error": f"analysis file is missing: {exc}"}, 410)
        except (ValueError, TypeError) as exc:
            self._json({"error": str(exc)}, 400)


def create_studio_server(root: str | Path, host: str = "127.0.0.1", port: int = 8876) -> ThreadingHTTPServer:
    store = WorkspaceStore.open(root)

    class Handler(_StudioHandler):
        pass

    Handler.store = store
    return ThreadingHTTPServer((host, port), Handler)


def serve_studio(
    root: str | Path,
    host: str = "127.0.0.1",
    port: int = 8876,
    *,
    open_browser: bool = False,
) -> None:
    server = create_studio_server(root, host, port)
    actual_host, actual_port = server.server_address[:2]
    browser_host = "127.0.0.1" if actual_host in {"0.0.0.0", "::"} else str(actual_host)
    url = f"http://{browser_host}:{actual_port}/"
    print(f"BLCReverseLab Studio: {url}")
    print("Mode: read-only. Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.15, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
