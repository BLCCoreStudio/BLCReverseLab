from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def render_analysis_html(report: dict[str, Any]) -> str:
    facts = dict(report.get("facts") or {})
    recovery = dict(facts.get("recovery") or {})
    ghidra = dict(facts.get("ghidra") or {})
    protection = dict(facts.get("protection") or {})
    crossref = dict(facts.get("jni_crossrefs") or {})
    hotspots = dict(facts.get("decompiler_hotspots") or {})
    evidence = [item for item in (report.get("evidence") or []) if isinstance(item, dict)]
    engines = ", ".join(facts.get("detected_engines") or []) or "—"

    cards = [
        ("Artifact", report.get("file_type", "unknown")), ("Engines", engines),
        ("Evidence", len(evidence)), ("Obfuscation", recovery.get("obfuscation_score", 0)),
        ("Native functions", ghidra.get("function_count", 0)),
        ("JNI links", crossref.get("matched_declaration_count", 0)),
        ("Protection", protection.get("level", "none")), ("Hotspots", hotspots.get("hotspot_count", 0)),
    ]
    card_html = "".join(f'<div class="card"><span>{_e(k)}</span><strong>{_e(v)}</strong></div>' for k, v in cards)
    signals = "".join(f"<li><b>{_e(i.get('name'))}</b><small>{_e(i.get('category'))} · {_e(i.get('confidence'))}</small></li>" for i in protection.get("signals") or []) or "<li>Strong protector fingerprint not detected.</li>"
    links = "".join(f"<tr><td>{_e(i.get('class_name'))}.{_e(i.get('method_name'))}</td><td>{_e(', '.join(i.get('matches') or []) or 'unresolved')}</td></tr>" for i in (crossref.get("declarations") or [])[:250]) or '<tr><td colspan="2">No indexed JNI declarations.</td></tr>'
    hotspot_rows = "".join(f"<tr><td>{_e(i.get('source_file'))}</td><td>{_e(i.get('reason'))}</td><td>{_e(i.get('score'))}</td></tr>" for i in (hotspots.get("hotspots") or [])[:100]) or '<tr><td colspan="3">No hotspots indexed.</td></tr>'
    evidence_rows = "".join(
        f'<tr class="ev" data-search="{_e(" ".join([str(i.get("id","")),str(i.get("kind","")),str(i.get("source","")),str(i.get("summary",""))]).lower())}"><td><code>{_e(i.get("id"))}</code></td><td>{_e(i.get("kind"))}</td><td>{_e(i.get("source"))}</td><td>{_e(i.get("summary"))}</td></tr>'
        for i in evidence[:3000]
    )
    raw_json = json.dumps(report, separators=(",", ":"), ensure_ascii=False).replace("</", "<\\/")

    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BLCReverseLab Workspace</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;font-family:Inter,ui-sans-serif,system-ui;background:#080b10;color:#eef2f7}}
header{{position:sticky;top:0;z-index:2;background:#0d121bcc;border-bottom:1px solid #252d38;backdrop-filter:blur(18px)}}nav,main{{max-width:1280px;margin:auto;padding:18px 28px}}nav{{display:flex;align-items:center;justify-content:space-between}}h1{{font-size:20px;margin:0}}.pill{{border:1px solid #303946;background:#151b24;padding:7px 11px;border-radius:999px;color:#a9b5c4}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px;margin:18px 0}}.card,section{{background:linear-gradient(180deg,#121923,#0f151e);border:1px solid #252e3a;border-radius:16px;box-shadow:0 16px 40px #0003}}.card{{padding:16px}}.card span{{font-size:11px;color:#8290a3;text-transform:uppercase;letter-spacing:.09em}}.card strong{{display:block;font-size:22px;margin-top:7px}}section{{padding:20px;margin-top:14px}}h2{{font-size:16px;margin:0 0 14px}}table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{padding:10px;border-bottom:1px solid #202936;text-align:left;vertical-align:top}}th{{color:#8290a3}}code{{color:#b9d7ff}}input{{width:100%;background:#080d14;border:1px solid #2b3644;border-radius:10px;padding:11px;color:white;margin-bottom:10px}}ul{{padding-left:18px}}li{{margin:8px 0}}li small{{display:block;color:#8290a3;margin-top:2px}}.muted{{color:#8290a3;font-size:13px}}details pre{{white-space:pre-wrap;word-break:break-word;max-height:500px;overflow:auto}}
</style></head><body><header><nav><h1>BLCReverseLab <span class="muted">Workspace</span></h1><span class="pill">{_e(report.get('file_type','unknown')).upper()}</span></nav></header><main>
<div class="grid">{card_html}</div>
<section><h2>Target</h2><div class="muted">{_e(report.get('target'))}</div><p><code>{_e(report.get('sha256'))}</code></p></section>
<section><h2>Protection & recovery</h2><ul>{signals}</ul></section>
<section><h2>Java → JNI → Native</h2><table><thead><tr><th>Managed declaration</th><th>Native correlation</th></tr></thead><tbody>{links}</tbody></table></section>
<section><h2>Decompiler hotspots</h2><table><thead><tr><th>Source</th><th>Reason</th><th>Score</th></tr></thead><tbody>{hotspot_rows}</tbody></table></section>
<section><h2>Evidence Explorer</h2><input id="q" placeholder="Search evidence, kind, source or summary…"><table><thead><tr><th>ID</th><th>Kind</th><th>Source</th><th>Summary</th></tr></thead><tbody>{evidence_rows}</tbody></table></section>
<section><details><summary>Raw machine report</summary><pre id="raw"></pre></details></section>
<script type="application/json" id="data">{raw_json}</script><script>
const q=document.getElementById('q');q.addEventListener('input',()=>{{const v=q.value.toLowerCase();document.querySelectorAll('.ev').forEach(r=>r.hidden=!r.dataset.search.includes(v));}});
const d=JSON.parse(document.getElementById('data').textContent);document.getElementById('raw').textContent=JSON.stringify(d,null,2);
</script></main></body></html>"""


def save_analysis_html(report: dict[str, Any], output: str | Path) -> Path:
    path=Path(output); path.parent.mkdir(parents=True,exist_ok=True); path.write_text(render_analysis_html(report),encoding="utf-8"); return path
