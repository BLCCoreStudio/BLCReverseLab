from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(slots=True)
class AnalysisDiff:
    added_native: list[str]
    removed_native: list[str]
    added_dex: list[str]
    removed_dex: list[str]
    engines_before: list[str]
    engines_after: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compare(before: dict[str, Any], after: dict[str, Any]) -> AnalysisDiff:
    bf = before.get("facts", {})
    af = after.get("facts", {})
    bn, an = set(bf.get("native_libraries", [])), set(af.get("native_libraries", []))
    bd, ad = set(bf.get("dex_files", [])), set(af.get("dex_files", []))
    return AnalysisDiff(
        added_native=sorted(an - bn),
        removed_native=sorted(bn - an),
        added_dex=sorted(ad - bd),
        removed_dex=sorted(bd - ad),
        engines_before=list(bf.get("detected_engines", [])),
        engines_after=list(af.get("detected_engines", [])),
    )
