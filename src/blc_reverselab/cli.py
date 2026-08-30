from __future__ import annotations

import argparse
import json
from pathlib import Path

from .diff import compare
from .native import GhidraStep
from .pipeline import Pipeline


def _load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(prog="blc-reverselab")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze an authorized artifact")
    analyze.add_argument("target")
    analyze.add_argument("-o", "--output", default="analysis.json")
    analyze.add_argument(
        "--jadx",
        action="store_true",
        help="Run the optional JADX adapter and index its decompilation output",
    )
    analyze.add_argument(
        "--recover",
        action="store_true",
        help="Enable JADX deobfuscation plus the readable-code recovery profiler",
    )
    analyze.add_argument(
        "--mapping",
        type=Path,
        help="Optional developer-supplied rename mapping (for example ProGuard/R8 mapping.txt)",
    )
    analyze.add_argument(
        "--ghidra",
        action="store_true",
        help="Run optional Ghidra Headless analysis for native binaries/libraries",
    )
    analyze.add_argument(
        "--ghidra-timeout",
        type=int,
        default=300,
        help="Ghidra analysis timeout per native target in seconds (default: 300)",
    )
    analyze.add_argument(
        "--ghidra-max-native",
        type=int,
        default=8,
        help="Maximum native libraries extracted from a package for Ghidra analysis (default: 8)",
    )
    analyze.add_argument(
        "--workdir",
        default=".blc-reverselab",
        help="Directory used by optional external-analysis adapters",
    )

    diff = sub.add_parser("diff", help="Compare two saved analyses")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument("-o", "--output", help="Optionally save the version-intelligence JSON")

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
        ctx = pipeline.analyze(args.target)
        out = Pipeline.save(ctx, args.output)
        print(json.dumps(ctx.to_dict(), indent=2, sort_keys=True))
        print(f"\nSaved: {out}")
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
