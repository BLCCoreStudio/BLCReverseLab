from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(slots=True)
class AnalysisDiff:
    added_native: list[str]
    removed_native: list[str]
    changed_native: list[str]
    added_dex: list[str]
    removed_dex: list[str]
    changed_dex: list[str]
    added_tracked_entries: list[str]
    removed_tracked_entries: list[str]
    changed_tracked_entries: list[str]
    manifest_changed: bool
    resource_entry_delta: int
    engines_before: list[str]
    engines_after: list[str]
    evidence_added: list[str]
    evidence_removed: list[str]
    analysis_reuse_ratio: float

    @property
    def change_count(self) -> int:
        return (
            len(self.added_tracked_entries)
            + len(self.removed_tracked_entries)
            + len(self.changed_tracked_entries)
            + len(self.evidence_added)
            + len(self.evidence_removed)
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["change_count"] = self.change_count
        return data


def _evidence_ids(report: dict[str, Any]) -> set[str]:
    return {
        str(item["id"])
        for item in report.get("evidence", [])
        if isinstance(item, dict) and item.get("id")
    }


def compare(before: dict[str, Any], after: dict[str, Any]) -> AnalysisDiff:
    bf = before.get("facts", {})
    af = after.get("facts", {})
    bn, an = set(bf.get("native_libraries", [])), set(af.get("native_libraries", []))
    bd, ad = set(bf.get("dex_files", [])), set(af.get("dex_files", []))

    before_tracked = dict(bf.get("tracked_entries") or {})
    after_tracked = dict(af.get("tracked_entries") or {})
    bt, at = set(before_tracked), set(after_tracked)
    shared = bt & at
    changed = sorted(name for name in shared if before_tracked[name] != after_tracked[name])
    unchanged = shared - set(changed)

    changed_native = sorted(
        name
        for name in changed
        if (after_tracked.get(name) or before_tracked.get(name) or {}).get("kind") == "native"
    )
    changed_dex = sorted(
        name
        for name in changed
        if (after_tracked.get(name) or before_tracked.get(name) or {}).get("kind") == "dex"
    )
    manifest_names = {
        name
        for name, record in {**before_tracked, **after_tracked}.items()
        if record.get("kind") == "manifest"
    }
    manifest_changed = bool(manifest_names & ((bt ^ at) | set(changed)))

    if bt or at:
        union_count = len(bt | at)
        reuse_ratio = len(unchanged) / union_count if union_count else 1.0
    else:
        before_inventory = bn | bd
        after_inventory = an | ad
        union_count = len(before_inventory | after_inventory)
        reuse_ratio = len(before_inventory & after_inventory) / union_count if union_count else 1.0

    before_evidence = _evidence_ids(before)
    after_evidence = _evidence_ids(after)

    return AnalysisDiff(
        added_native=sorted(an - bn),
        removed_native=sorted(bn - an),
        changed_native=changed_native,
        added_dex=sorted(ad - bd),
        removed_dex=sorted(bd - ad),
        changed_dex=changed_dex,
        added_tracked_entries=sorted(at - bt),
        removed_tracked_entries=sorted(bt - at),
        changed_tracked_entries=changed,
        manifest_changed=manifest_changed,
        resource_entry_delta=int(af.get("resource_entry_count", 0)) - int(bf.get("resource_entry_count", 0)),
        engines_before=list(bf.get("detected_engines", [])),
        engines_after=list(af.get("detected_engines", [])),
        evidence_added=sorted(after_evidence - before_evidence),
        evidence_removed=sorted(before_evidence - after_evidence),
        analysis_reuse_ratio=round(reuse_ratio, 4),
    )
