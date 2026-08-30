from __future__ import annotations

from collections import defaultdict
from typing import Any


def _targets(report: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    facts = dict(report.get("facts") or {})
    ghidra = dict(facts.get("ghidra") or {})
    result: dict[str, list[dict[str, Any]]] = {}
    for index, item in enumerate(ghidra.get("results") or []):
        key = str(item.get("archive_member") or item.get("target") or f"target-{index}")
        result[key] = [
            dict(entry)
            for entry in (item.get("function_fingerprints") or [])
            if isinstance(entry, dict)
        ]
    return result


def _unique_by(items: list[dict[str, Any]], field: str) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        value = str(item.get(field) or "")
        if value:
            groups[value].append(item)
    return {key: values[0] for key, values in groups.items() if len(values) == 1}


def match_native_functions(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    bt = _targets(before)
    at = _targets(after)
    matches: list[dict[str, Any]] = []
    total_before = sum(len(items) for items in bt.values())
    total_after = sum(len(items) for items in at.values())

    for target in sorted(set(bt) & set(at)):
        before_items = bt[target]
        after_items = at[target]
        matched_before: set[str] = set()
        matched_after: set[str] = set()

        named_before = _unique_by(
            [item for item in before_items if not item.get("generic_name") and not item.get("external")],
            "name",
        )
        named_after = _unique_by(
            [item for item in after_items if not item.get("generic_name") and not item.get("external")],
            "name",
        )
        for name in sorted(set(named_before) & set(named_after)):
            left, right = named_before[name], named_after[name]
            matches.append(
                {
                    "target": target,
                    "method": "stable-name",
                    "confidence": 1.0,
                    "before_name": left.get("name"),
                    "after_name": right.get("name"),
                    "before_address": left.get("address"),
                    "after_address": right.get("address"),
                    "shape_id": right.get("shape_id") or left.get("shape_id"),
                }
            )
            matched_before.add(str(left.get("address") or left.get("name")))
            matched_after.add(str(right.get("address") or right.get("name")))

        remaining_before = [
            item
            for item in before_items
            if str(item.get("address") or item.get("name")) not in matched_before
            and not item.get("external")
        ]
        remaining_after = [
            item
            for item in after_items
            if str(item.get("address") or item.get("name")) not in matched_after
            and not item.get("external")
        ]
        shape_before = _unique_by(remaining_before, "shape_id")
        shape_after = _unique_by(remaining_after, "shape_id")
        for shape_id in sorted(set(shape_before) & set(shape_after)):
            left, right = shape_before[shape_id], shape_after[shape_id]
            matches.append(
                {
                    "target": target,
                    "method": "unique-shape",
                    "confidence": 0.78,
                    "before_name": left.get("name"),
                    "after_name": right.get("name"),
                    "before_address": left.get("address"),
                    "after_address": right.get("address"),
                    "shape_id": shape_id,
                }
            )
            matched_before.add(str(left.get("address") or left.get("name")))
            matched_after.add(str(right.get("address") or right.get("name")))

    matched = len(matches)
    denominator = max(total_before, total_after, 1)
    return {
        "native_functions_before": total_before,
        "native_functions_after": total_after,
        "native_semantic_match_count": matched,
        "native_function_reuse_ratio": round(matched / denominator, 4),
        "native_unmatched_before": max(0, total_before - matched),
        "native_unmatched_after": max(0, total_after - matched),
        "native_semantic_matches": matches[:1000],
    }
