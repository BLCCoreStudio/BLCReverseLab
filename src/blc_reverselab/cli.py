from __future__ import annotations

import argparse
import json
from pathlib import Path

from .bundle import create_bundle
from .diff import compare
from .doctor import doctor
from .pipeline import Pipeline
from .profiles import build_pipeline
from .query import search_report
from .report import save_analysis_html
from .runtime import enrich_with_runtime_observations
from .server import serve_workspace
from .workspace import add_analysis, init_workspace, read_workspace


def _load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(prog="blc-reverselab")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze an authorized artifact")
    analyze.add_argument("target")
    analyze.add_argument("-o", "--output", default="analysis.json")
    analyze.add_argument("--jadx", action="store_true")
    analyze.add_argument("--recover", action="store_true")
    analyze.add_argument("--mapping", type=Path)
    analyze.add_argument("--ghidra", action="store_true")
    analyze.add_argument("--deep", action="store_true", help="Enable managed recovery + native analysis + correlation")
    analyze.add_argument("--ghidra-timeout", type=int, default=300)
    analyze.add_argument("--ghidra-max-native", type=int, default=8)
    analyze.add_argument("--html-report", type=Path)
    analyze.add_argument("--workdir", default=".blc-reverselab")

    diff = sub.add_parser("diff", help="Compare two saved analyses")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument("-o", "--output")

    report = sub.add_parser("report", help="Render a saved analysis as interactive HTML")
    report.add_argument("analysis")
    report.add_argument("-o", "--output", default="reverselab-report.html")

    bundle = sub.add_parser("bundle", help="Create a portable review bundle")
    bundle.add_argument("analysis")
    bundle.add_argument("--version-diff", type=Path)
    bundle.add_argument("-o", "--output", default="reverselab.blc.zip")

    search = sub.add_parser("search", help="Universal search across a saved analysis")
    search.add_argument("analysis")
    search.add_argument("query")
    search.add_argument("--limit", type=int, default=100)

    sub.add_parser("doctor", help="Inspect optional analysis-tool readiness")

    enrich = sub.add_parser("enrich", help="Attach authorized runtime observations to a static analysis")
    enrich.add_argument("analysis")
    enrich.add_argument("--runtime", required=True, type=Path)
    enrich.add_argument("-o", "--output", default="analysis.enriched.json")

    workspace = sub.add_parser("workspace", help="Manage persistent project history")
    ws = workspace.add_subparsers(dest="workspace_command", required=True)
    wsi = ws.add_parser("init")
    wsi.add_argument("root")
    wsi.add_argument("--name", required=True)
    wsa = ws.add_parser("add")
    wsa.add_argument("root")
    wsa.add_argument("analysis")
    wss = ws.add_parser("status")
    wss.add_argument("root")

    serve = sub.add_parser("serve", help="Open the local read-only workspace IDE")
    serve.add_argument("root", help="Workspace directory containing blc-workspace.json")
    serve.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    serve.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765; 0 selects a free port)")
    serve.add_argument("--open", action="store_true", dest="open_browser", help="Open the workspace in the default browser")

    args = parser.parse_args()

    if args.command == "analyze":
        pipeline = build_pipeline(
            enable_jadx=args.jadx or args.recover,
            enable_recovery=args.recover,
            enable_ghidra=args.ghidra,
            deep=args.deep,
            mappings_path=args.mapping,
            workdir=args.workdir,
            ghidra_timeout=args.ghidra_timeout,
            ghidra_max_native=args.ghidra_max_native,
        )
        ctx = pipeline.analyze(args.target)
        out = Pipeline.save(ctx, args.output)
        payload = ctx.to_dict()
        print(json.dumps(payload, indent=2, sort_keys=True))
        print(f"\nSaved: {out}")
        if args.html_report:
            print(f"HTML: {save_analysis_html(payload, args.html_report)}")
        return

    if args.command == "diff":
        result = compare(_load(args.before), _load(args.after))
        payload = json.dumps(result.to_dict(), indent=2, sort_keys=True)
        print(payload)
        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(payload + "\n", encoding="utf-8")
            print(f"\nSaved: {output}")
        return

    if args.command == "report":
        print(f"Saved: {save_analysis_html(_load(args.analysis), args.output)}")
        return

    if args.command == "bundle":
        print(
            f"Saved: {create_bundle(_load(args.analysis), args.output, version_diff=_load(args.version_diff) if args.version_diff else None)}"
        )
        return

    if args.command == "search":
        print(json.dumps(search_report(_load(args.analysis), args.query, limit=max(1, args.limit)), indent=2, sort_keys=True))
        return

    if args.command == "doctor":
        print(json.dumps(doctor(), indent=2, sort_keys=True))
        return

    if args.command == "enrich":
        enriched = enrich_with_runtime_observations(_load(args.analysis), _load(args.runtime))
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(enriched, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"Saved: {output}")
        return

    if args.command == "serve":
        serve_workspace(args.root, host=args.host, port=max(0, args.port), open_browser=args.open_browser)
        return

    if args.workspace_command == "init":
        print(f"Saved: {init_workspace(args.root, args.name)}")
    elif args.workspace_command == "add":
        print(f"Saved: {add_analysis(args.root, args.analysis)}")
    else:
        print(json.dumps(read_workspace(args.root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
