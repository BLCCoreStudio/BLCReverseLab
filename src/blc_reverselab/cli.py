from __future__ import annotations

import argparse
import json
from pathlib import Path

from .crossref import JniCrossReferenceStep
from .diff import compare
from .native import GhidraStep
from .pipeline import Pipeline
from .protection import ProtectionStep
from .report import save_analysis_html


def _load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(prog="blc-reverselab")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze an authorized artifact")
    analyze.add_argument("target")
    analyze.add_argument("-o", "--output", default="analysis.json")
    analyze.add_argument("--jadx", action="store_true", help="Run the optional JADX adapter")
    analyze.add_argument("--recover", action="store_true", help="Enable deobfuscation/readability recovery")
    analyze.add_argument("--mapping", type=Path, help="Optional developer-supplied ProGuard/R8 mapping")
    analyze.add_argument("--ghidra", action="store_true", help="Run optional Ghidra Headless native analysis")
    analyze.add_argument("--ghidra-timeout", type=int, default=300)
    analyze.add_argument("--ghidra-max-native", type=int, default=8)
    analyze.add_argument("--html-report", type=Path, help="Also write a self-contained HTML report")
    analyze.add_argument("--workdir", default=".blc-reverselab")

    diff = sub.add_parser("diff", help="Compare two saved analyses")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument("-o", "--output")

    report = sub.add_parser("report", help="Render a saved analysis as self-contained HTML")
    report.add_argument("analysis")
    report.add_argument("-o", "--output", default="reverselab-report.html")

    args = parser.parse_args()
    if args.command == "analyze":
        workdir = Path(args.workdir)
        pipeline = Pipeline(
            enable_jadx=args.jadx or args.recover,
            enable_recovery=args.recover,
            mappings_path=args.mapping,
            workdir=workdir,
        )
        if args.ghidra:
            pipeline.steps.append(
                GhidraStep(
                    workdir,
                    timeout_seconds=max(30, args.ghidra_timeout),
                    max_native_targets=max(1, args.ghidra_max_native),
                )
            )
        pipeline.steps.append(ProtectionStep())
        if args.jadx or args.recover or args.ghidra:
            pipeline.steps.append(JniCrossReferenceStep())

        ctx = pipeline.analyze(args.target)
        out = Pipeline.save(ctx, args.output)
        payload = ctx.to_dict()
        print(json.dumps(payload, indent=2, sort_keys=True))
        print(f"\nSaved: {out}")
        if args.html_report:
            html_path = save_analysis_html(payload, args.html_report)
            print(f"HTML: {html_path}")
        return

    if args.command == "report":
        output = save_analysis_html(_load(args.analysis), args.output)
        print(f"Saved: {output}")
        return

    result = compare(_load(args.before), _load(args.after))
    payload = json.dumps(result.to_dict(), indent=2, sort_keys=True)
    print(payload)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload + "\n", encoding="utf-8")
        print(f"\nSaved: {output}")


if __name__ == "__main__":
    main()
