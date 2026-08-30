from __future__ import annotations

import html
from pathlib import Path
from typing import Any


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def render_analysis_html(report: dict[str, Any]) -> str:
    facts = dict(report.get("facts") or {})
    recovery = dict(facts.get("recovery") or {})
    ghidra = dict(facts.get("ghidra") or {})
    protection = dict(facts.get("protection") or {})
    crossref = dict(facts.get("jni_crossrefs") or {})
    evidence = list(report.get("evidence") or [])
    engines = ", ".join(facts.get("detected_engines") or []) or "—"

    cards = [
        ("Artifact", report.get("file_type", "unknown")),
        ("Engines", engines),
        ("Evidence", len(evidence)),
        ("Obfuscation", recovery.get("obfuscation_score", 0)),
        ("Native functions", ghidra.get("function_count", 0)),
        ("JNI links", crossref.get("matched_declaration_count", 0)),
        ("Protection", protection.get("level", "none")),
    ]

    card_html = "".join(
        f'<div class="card"><div class="label">{_esc(label)}</div><div class="value">{_esc(value)}</div></div>'
        for label, value in cards
    )
    signals = "".join(
        f"<li><b>{_esc(item.get('name'))}</b> — {_esc(item.get('category'))} "
        f"(confidence {_esc(item.get('confidence'))})</li>"
        for item in protection.get("signals") or []
    ) or "<li>No strong protection fingerprint detected.</li>"
    links = "".join(
        f"<li>{_esc(item.get('class_name'))}.{_esc(item.get('method_name'))} → "
        f"{_esc(', '.join(item.get('matches') or []) or 'unresolved')}</li>"
        for item in (crossref.get("declarations") or [])[:100]
    ) or "<li>No Java/native declarations indexed.</li>"

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BLCReverseLab Report</title>
<style>
body{{font-family:Inter,system-ui,sans-serif;margin:0;background:#0d1117;color:#e6edf3}}
main{{max-width:1180px;margin:auto;padding:32px}}
h1{{margin:0 0 8px}} .muted{{color:#8b949e}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:24px 0}}
.card,section{{background:#161b22;border:1px solid #30363d;border-radius:14px;padding:18px}}
.label{{font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:.08em}}
.value{{font-size:24px;font-weight:700;margin-top:6px;word-break:break-word}}
section{{margin-top:14px}} code{{word-break:break-all}} li{{margin:8px 0}}
</style>
</head>
<body><main>
<h1>BLCReverseLab</h1>
<div class="muted">Evidence-first authorized reverse-engineering report</div>
<div class="grid">{card_html}</div>
<section><h2>Target</h2><code>{_esc(report.get("target"))}</code><p>SHA-256: <code>{_esc(report.get("sha256"))}</code></p></section>
<section><h2>Protection & recovery signals</h2><ul>{signals}</ul></section>
<section><h2>Java ↔ JNI ↔ native links</h2><ul>{links}</ul></section>
<section><h2>Pipeline</h2><p>{_esc(" → ".join(report.get("completed_steps") or []))}</p></section>
</main></body></html>"""


def save_analysis_html(report: dict[str, Any], output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_analysis_html(report), encoding="utf-8")
    return path
