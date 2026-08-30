from __future__ import annotations

import argparse
import json
from pathlib import Path

from .diff import compare
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
        pipeline = Pipeline(enable_jadx=args.jadx, workdir=args.workdir)
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
