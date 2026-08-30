from __future__ import annotations

import argparse
import json
from pathlib import Path

from .diff import compare
from .pipeline import Pipeline


def _load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(prog="blc-reverselab")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="Analyze an authorized artifact")
    a.add_argument("target")
    a.add_argument("-o", "--output", default="analysis.json")

    d = sub.add_parser("diff", help="Compare two saved analyses")
    d.add_argument("before")
    d.add_argument("after")

    args = parser.parse_args()
    if args.command == "analyze":
        ctx = Pipeline().analyze(args.target)
        out = Pipeline.save(ctx, args.output)
        print(json.dumps(ctx.to_dict(), indent=2))
        print(f"\nSaved: {out}")
    else:
        result = compare(_load(args.before), _load(args.after))
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
