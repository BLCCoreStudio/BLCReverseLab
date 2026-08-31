from __future__ import annotations

import json
import threading
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .diff import compare
from .query import search_report
from .report import render_analysis_html
from .workspace import read_workspace


@dataclass(slots=True)
class WorkspaceStore:
    root: Path

    @classmethod
    def open(cls, root: str | Path) -> "WorkspaceStore":
        path = Path(root).expanduser().resolve()
        # Fail early with the same contract as workspace status.
        read_workspace(path)
        return cls(path)

    def workspace(self) -> dict[str, Any]:
        return read_workspace(self.root)

    def _entry_map(self) -> dict[str, dict[str, Any]]:
        entries = self.workspace().get("analyses") or []
        return {
            str(item.get("sha256")): dict(item)
            for item in entries
            if isinstance(item, dict) and item.get("sha256")
        }

    def load_analysis(self, sha256: str) -> dict[str, Any]:
        entry = self._entry_map().get(sha256)
        if entry is None:
            raise KeyError(sha256)
        path = Path(str(entry.get("analysis_path", ""))).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(path)
        return json.loads(path.read_text(encoding="utf-8"))

    def snapshot(self) -> dict[str, Any]:
        workspace = self.workspace()
        analyses: list[dict[str, Any]] = []
        for entry in workspace.get("analyses") or []:
            if not isinstance(entry, dict):
                continue
            item = dict(entry)
            path = Path(str(item.get("analysis_path", ""))).expanduser()
            item["available"] = path.is_file()
            if item["available"]:
                try:
                    report = json.loads(path.read_text(encoding="utf-8"))
                    facts = dict(report.get("facts") or {})
                    item["summary"] = {
                        "evidence_count": len(report.get("evidence") or []),
                        "engines": list(facts.get("detected_engines") or []),
                        "native_function_count": int(dict(facts.get("ghidra") or {}).get("function_count", 0)),
                        "protection_level": dict(facts.get("protection") or {}).get("level", "none"),
                        "obfuscation_score": float(dict(facts.get("recovery") or {}).get("obfuscation_score", 0.0)),
                    }
                except (OSError, ValueError, TypeError):
                    item["available"] = False
            analyses.append(item)
        return {
            "schema_version": workspace.get("schema_version"),
            "name": workspace.get("name", "BLCReverseLab Workspace"),
            "created_at": workspace.get("created_at"),
            "analysis_count": len(analyses),
            "analyses": analyses,
        }

    def search(self, sha256: str, query: str, limit: int = 100) -> dict[str, Any]:
        return search_report(self.load_analysis(sha256), query, limit=max(1, min(limit, 500)))

    def diff(self, before: str, after: str) -> dict[str, Any]:
        return compare(self.load_analysis(before), self.load_analysis(after)).to_dict()


def render_workspace_app(title: str = "BLCReverseLab Workspace") -> str:
    safe_title = title.replace("<", "&lt;").replace(">", "&gt;")
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{safe_title}</title>
<style>
:root{{color-scheme:dark;--bg:#070a0f;--panel:#0f151e;--panel2:#121a25;--line:#253142;--muted:#8695a8;--text:#eef4fb;--accent:#9fc7ff}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 20% -10%,#14233a 0,#080c13 34%,#070a0f 70%);color:var(--text);font-family:Inter,ui-sans-serif,system-ui}}
header{{position:sticky;top:0;z-index:4;background:#090d14dd;border-bottom:1px solid var(--line);backdrop-filter:blur(18px)}}nav{{max-width:1500px;margin:auto;padding:16px 24px;display:flex;align-items:center;justify-content:space-between;gap:16px}}h1{{font-size:18px;margin:0}}main{{max-width:1500px;margin:auto;padding:22px 24px 60px}}.muted{{color:var(--muted)}}.layout{{display:grid;grid-template-columns:320px minmax(0,1fr);gap:16px}}.panel{{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:16px;box-shadow:0 18px 50px #0005}}.sidebar{{padding:14px;height:calc(100vh - 110px);position:sticky;top:86px;overflow:auto}}.content{{padding:18px;min-height:70vh}}button,input,select{{font:inherit}}button{{cursor:pointer;border:1px solid #30415a;background:#131c28;color:var(--text);border-radius:10px;padding:9px 11px}}button:hover{{border-color:#49698f}}button.active{{background:#20324a;border-color:#5a82b4}}input,select{{width:100%;background:#080d14;color:var(--text);border:1px solid #2a3748;border-radius:10px;padding:10px}}.analysis{{width:100%;text-align:left;margin:5px 0;padding:11px}}.analysis strong{{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}.analysis small{{display:block;color:var(--muted);margin-top:4px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:10px;margin:14px 0}}.card{{padding:14px;border:1px solid var(--line);background:#0b1119;border-radius:13px}}.card span{{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.07em}}.card strong{{display:block;font-size:20px;margin-top:5px}}.toolbar{{display:grid;grid-template-columns:1fr auto;gap:8px;margin:12px 0}}table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{padding:9px;border-bottom:1px solid #1e2938;text-align:left;vertical-align:top}}th{{color:var(--muted)}}code{{color:#b9d8ff}}.section{{margin-top:18px;padding-top:15px;border-top:1px solid var(--line)}}.pill{{display:inline-block;border:1px solid #33445a;background:#101925;border-radius:999px;padding:5px 9px;color:#b9c8db;font-size:12px}}.two{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}pre{{white-space:pre-wrap;word-break:break-word;background:#080d14;border:1px solid #1d2938;border-radius:12px;padding:12px;max-height:420px;overflow:auto}}iframe{{width:100%;height:78vh;border:1px solid var(--line);border-radius:12px;background:#080b10}}@media(max-width:850px){{.layout{{grid-template-columns:1fr}}.sidebar{{position:static;height:auto}}.two{{grid-template-columns:1fr}}}}
</style></head>
<body><header><nav><h1>BLCReverseLab <span class="muted">Local Workspace IDE</span></h1><span class="pill" id="health">connecting…</span></nav></header>
<main><div class="layout"><aside class="panel sidebar"><input id="filter" placeholder="Filter analyses…"><div id="analyses"></div></aside><section class="panel content"><div id="view"><h2>Workspace</h2><p class="muted">Select an analysis from the left.</p></div></section></div></main>
<script>
const S={{workspace:null,current:null,currentReport:null}};
const esc=s=>String(s??'').replace(/[&<>\"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}}[c]));
async function api(path){{const r=await fetch(path,{{cache:'no-store'}});if(!r.ok)throw new Error((await r.json().catch(()=>({{error:r.statusText}}))).error||r.statusText);return r.json();}}
function renderList(){{const q=document.getElementById('filter').value.toLowerCase();const box=document.getElementById('analyses');box.innerHTML='';for(const a of S.workspace.analyses){{const hay=(a.target+' '+a.sha256+' '+(a.file_type||'')).toLowerCase();if(!hay.includes(q))continue;const b=document.createElement('button');b.className='analysis'+(S.current===a.sha256?' active':'');b.innerHTML=`<strong>${{esc((a.target||'').split('/').pop()||a.sha256)}}</strong><small>${{esc(a.file_type||'unknown')}} · ${{esc((a.sha256||'').slice(0,12))}} · ${{a.available?'ready':'missing'}}</small>`;b.disabled=!a.available;b.onclick=()=>selectAnalysis(a.sha256);box.appendChild(b);}}}}
function card(k,v){{return `<div class="card"><span>${{esc(k)}}</span><strong>${{esc(v)}}</strong></div>`}}
async function selectAnalysis(sha){{S.current=sha;renderList();const r=await api('/api/analysis/'+encodeURIComponent(sha));S.currentReport=r;const f=r.facts||{{}},g=f.ghidra||{{}},rec=f.recovery||{{}},p=f.protection||{{}},x=f.jni_crossrefs||{{}};document.getElementById('view').innerHTML=`<h2>${{esc((r.target||'').split('/').pop()||sha)}}</h2><p class="muted"><code>${{esc(sha)}}</code></p><div class="grid">${{card('Artifact',r.file_type||'unknown')}}${{card('Evidence',(r.evidence||[]).length)}}${{card('Native funcs',g.function_count||0)}}${{card('JNI links',x.matched_declaration_count||0)}}${{card('Protection',p.level||'none')}}${{card('Obfuscation',rec.obfuscation_score||0)}}</div><div class="section"><h3>Universal search</h3><div class="toolbar"><input id="q" placeholder="classes, methods, endpoints, native functions, JNI, evidence…"><button id="go">Search</button></div><div id="results" class="muted">Enter a query.</div></div><div class="section"><h3>Version intelligence</h3><div class="two"><select id="before"></select><button id="diff">Compare selected → current</button></div><div id="diffout"></div></div><div class="section"><h3>Full analysis view</h3><button id="openReport">Open embedded report</button><div id="frame"></div></div>`;
const sel=document.getElementById('before');for(const a of S.workspace.analyses){{if(a.sha256===sha||!a.available)continue;const o=document.createElement('option');o.value=a.sha256;o.textContent=((a.target||'').split('/').pop()||a.sha256)+' · '+a.sha256.slice(0,10);sel.appendChild(o);}}
document.getElementById('go').onclick=runSearch;document.getElementById('q').addEventListener('keydown',e=>{{if(e.key==='Enter')runSearch();}});document.getElementById('diff').onclick=runDiff;document.getElementById('openReport').onclick=()=>{{document.getElementById('frame').innerHTML=`<iframe src="/analysis/${{encodeURIComponent(sha)}}"></iframe>`;}};}}
async function runSearch(){{const q=document.getElementById('q').value.trim();if(!q)return;const data=await api('/api/search?sha='+encodeURIComponent(S.current)+'&q='+encodeURIComponent(q)+'&limit=100');const rows=(data.results||data.matches||[]);const out=document.getElementById('results');if(!rows.length){{out.innerHTML='<p class="muted">No matches.</p>';return;}}out.innerHTML='<table><thead><tr><th>Layer</th><th>Location</th><th>Value</th></tr></thead><tbody>'+rows.slice(0,100).map(i=>`<tr><td>${{esc(i.layer||i.kind||i.type||'result')}}</td><td><code>${{esc(i.location||i.path||i.id||'')}}</code></td><td>${{esc(i.value||i.summary||i.name||JSON.stringify(i))}}</td></tr>`).join('')+'</tbody></table>';}}
async function runDiff(){{const before=document.getElementById('before').value;if(!before)return;const d=await api('/api/diff?before='+encodeURIComponent(before)+'&after='+encodeURIComponent(S.current));document.getElementById('diffout').innerHTML='<pre>'+esc(JSON.stringify(d,null,2))+'</pre>';}}
async function boot(){{try{{await api('/api/health');document.getElementById('health').textContent='local · read only';S.workspace=await api('/api/workspace');document.title=S.workspace.name+' · BLCReverseLab';renderList();if(S.workspace.analyses.length){{const a=[...S.workspace.analyses].reverse().find(x=>x.available);if(a)await selectAnalysis(a.sha256);}}}}catch(e){{document.getElementById('health').textContent='error';document.getElementById('view').innerHTML='<h2>Workspace error</h2><pre>'+esc(e.message)+'</pre>';}}}}
document.getElementById('filter').addEventListener('input',renderList);boot();
</script></body></html>"""


class _WorkspaceHandler(BaseHTTPRequestHandler):
    store: WorkspaceStore

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return

    def _headers(self, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-src 'self'",
        )
        self.end_headers()

    def _json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        self._headers("application/json; charset=utf-8", status)
        self.wfile.write(body)

    def _html(self, body: str, status: int = 200) -> None:
        self._headers("text/html; charset=utf-8", status)
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/":
                self._html(render_workspace_app(self.store.workspace().get("name", "BLCReverseLab Workspace")))
                return
            if parsed.path == "/api/health":
                self._json({"status": "ok", "mode": "read-only", "workspace": str(self.store.root)})
                return
            if parsed.path == "/api/workspace":
                self._json(self.store.snapshot())
                return
            if parsed.path.startswith("/api/analysis/"):
                sha256 = unquote(parsed.path.removeprefix("/api/analysis/"))
                self._json(self.store.load_analysis(sha256))
                return
            if parsed.path.startswith("/analysis/"):
                sha256 = unquote(parsed.path.removeprefix("/analysis/"))
                self._html(render_analysis_html(self.store.load_analysis(sha256)))
                return
            if parsed.path == "/api/search":
                params = parse_qs(parsed.query)
                sha256 = (params.get("sha") or [""])[0]
                query = (params.get("q") or [""])[0]
                limit = int((params.get("limit") or ["100"])[0])
                if not sha256 or not query:
                    self._json({"error": "sha and q are required"}, 400)
                    return
                self._json(self.store.search(sha256, query, limit))
                return
            if parsed.path == "/api/diff":
                params = parse_qs(parsed.query)
                before = (params.get("before") or [""])[0]
                after = (params.get("after") or [""])[0]
                if not before or not after:
                    self._json({"error": "before and after are required"}, 400)
                    return
                self._json(self.store.diff(before, after))
                return
            self._json({"error": "not found"}, 404)
        except KeyError:
            self._json({"error": "analysis not found in workspace"}, 404)
        except FileNotFoundError as exc:
            self._json({"error": f"analysis file is missing: {exc}"}, 410)
        except (ValueError, TypeError) as exc:
            self._json({"error": str(exc)}, 400)


def create_workspace_server(
    root: str | Path,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> ThreadingHTTPServer:
    store = WorkspaceStore.open(root)

    class Handler(_WorkspaceHandler):
        pass

    Handler.store = store
    return ThreadingHTTPServer((host, port), Handler)


def serve_workspace(
    root: str | Path,
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    open_browser: bool = False,
) -> None:
    server = create_workspace_server(root, host, port)
    actual_host, actual_port = server.server_address[:2]
    browser_host = "127.0.0.1" if actual_host in {"0.0.0.0", "::"} else str(actual_host)
    url = f"http://{browser_host}:{actual_port}/"
    print(f"BLCReverseLab workspace: {url}")
    print("Mode: read-only. Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.15, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
