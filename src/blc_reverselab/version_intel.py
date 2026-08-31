from __future__ import annotations

from typing import Any

from .diff import compare

_LEVELS = {"none": 0, "low": 1, "medium": 2, "high": 3}


def _managed(report: dict[str, Any]) -> dict[str, Any]:
    facts = dict(report.get("facts") or {})
    return dict(facts.get("managed_index") or {})


def _classes(report: dict[str, Any]) -> set[str]:
    return {
        str(item.get("name") or "")
        for item in (_managed(report).get("classes") or [])
        if isinstance(item, dict) and item.get("name")
    }


def _methods(report: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for item in _managed(report).get("methods") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        if not name:
            continue
        cls = str(item.get("class_name") or "")
        params = str(item.get("parameters") or "")
        values.add(f"{cls}.{name}({params})" if cls else f"{name}({params})")
    return values


def _endpoints(report: dict[str, Any]) -> set[str]:
    return {str(item) for item in (_managed(report).get("endpoints") or []) if item}


def _jni(report: dict[str, Any]) -> tuple[set[str], dict[str, Any]]:
    facts = dict(report.get("facts") or {})
    payload = dict(facts.get("jni_crossrefs") or {})
    values: set[str] = set()
    for item in payload.get("declarations") or []:
        if not isinstance(item, dict):
            continue
        cls = str(item.get("class_name") or "")
        method = str(item.get("method_name") or "")
        expected = str(item.get("expected_jni_symbol") or "")
        matches = ",".join(sorted(str(value) for value in (item.get("matches") or []) if value))
        values.add(f"{cls}.{method}|{expected}|{matches}")
    return values, payload


def _protection(report: dict[str, Any]) -> tuple[str, float, set[str]]:
    facts = dict(report.get("facts") or {})
    payload = dict(facts.get("protection") or {})
    signals = {
        f"{item.get('category', '')}:{item.get('name', '')}"
        for item in (payload.get("signals") or [])
        if isinstance(item, dict) and item.get("name")
    }
    return str(payload.get("level") or "none"), float(payload.get("score") or 0.0), signals


def _recovery(report: dict[str, Any]) -> dict[str, Any]:
    facts = dict(report.get("facts") or {})
    return dict(facts.get("recovery") or {})


def _delta(before: set[str], after: set[str]) -> dict[str, list[str]]:
    return {"added": sorted(after - before), "removed": sorted(before - after)}


def build_version_intelligence(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Create an evidence-conservative cross-layer build comparison.

    This enriches the stable low-level diff with managed/JNI/protection/recovery
    surfaces. It reports only differences present in the supplied analyses and
    never treats absent analysis data as proof that a feature does not exist.
    """
    base = compare(before, after).to_dict()

    before_classes, after_classes = _classes(before), _classes(after)
    before_methods, after_methods = _methods(before), _methods(after)
    before_endpoints, after_endpoints = _endpoints(before), _endpoints(after)
    before_jni, before_jni_payload = _jni(before)
    after_jni, after_jni_payload = _jni(after)
    before_level, before_protection_score, before_signals = _protection(before)
    after_level, after_protection_score, after_signals = _protection(after)
    before_recovery, after_recovery = _recovery(before), _recovery(after)

    managed = {
        "classes": _delta(before_classes, after_classes),
        "methods": _delta(before_methods, after_methods),
        "endpoints": _delta(before_endpoints, after_endpoints),
    }
    jni = {
        "bridges": _delta(before_jni, after_jni),
        "matched_before": int(before_jni_payload.get("matched_declaration_count", 0)),
        "matched_after": int(after_jni_payload.get("matched_declaration_count", 0)),
        "unresolved_before": int(before_jni_payload.get("unresolved_declaration_count", 0)),
        "unresolved_after": int(after_jni_payload.get("unresolved_declaration_count", 0)),
        "dynamic_registration_before": bool(before_jni_payload.get("dynamic_registration_signal", False)),
        "dynamic_registration_after": bool(after_jni_payload.get("dynamic_registration_signal", False)),
    }
    protection = {
        "level_before": before_level,
        "level_after": after_level,
        "score_before": round(before_protection_score, 3),
        "score_after": round(after_protection_score, 3),
        "score_delta": round(after_protection_score - before_protection_score, 3),
        "signals": _delta(before_signals, after_signals),
    }
    recovery = {
        "obfuscation_before": float(before_recovery.get("obfuscation_score", 0.0)),
        "obfuscation_after": float(after_recovery.get("obfuscation_score", 0.0)),
        "obfuscation_delta": round(
            float(after_recovery.get("obfuscation_score", 0.0))
            - float(before_recovery.get("obfuscation_score", 0.0)),
            3,
        ),
        "recovered_literals_before": int(before_recovery.get("recovered_literal_count", 0)),
        "recovered_literals_after": int(after_recovery.get("recovered_literal_count", 0)),
        "high_entropy_before": int(before_recovery.get("high_entropy_literal_count", 0)),
        "high_entropy_after": int(after_recovery.get("high_entropy_literal_count", 0)),
    }

    changed_surfaces: list[str] = []
    if any(managed[section][kind] for section in managed for kind in ("added", "removed")):
        changed_surfaces.append("managed")
    if jni["bridges"]["added"] or jni["bridges"]["removed"] or jni["matched_before"] != jni["matched_after"]:
        changed_surfaces.append("jni")
    if (
        base.get("added_native")
        or base.get("removed_native")
        or base.get("changed_native")
        or int(base.get("native_unmatched_after", 0))
    ):
        changed_surfaces.append("native")
    if protection["level_before"] != protection["level_after"] or protection["signals"]["added"] or protection["signals"]["removed"]:
        changed_surfaces.append("protection")
    if recovery["obfuscation_delta"] or recovery["recovered_literals_before"] != recovery["recovered_literals_after"] or recovery["high_entropy_before"] != recovery["high_entropy_after"]:
        changed_surfaces.append("recovery")
    if base.get("manifest_changed") or int(base.get("resource_entry_delta", 0)):
        changed_surfaces.append("android-structure")

    focus: list[dict[str, str]] = []
    if managed["methods"]["added"] or managed["methods"]["removed"]:
        focus.append({"surface": "managed", "reason": "Managed method surface changed; inspect affected call paths and evidence."})
    if managed["endpoints"]["added"] or managed["endpoints"]["removed"]:
        focus.append({"surface": "network", "reason": "Static endpoint candidates changed between builds."})
    if "jni" in changed_surfaces:
        focus.append({"surface": "jni", "reason": "Managed-to-native bridge inventory changed; re-check cross-layer correlations."})
    if "native" in changed_surfaces:
        focus.append({"surface": "native", "reason": "Native library/function identity changed; prioritize unmatched functions and changed libraries."})
    if _LEVELS.get(after_level, 0) > _LEVELS.get(before_level, 0) or protection["signals"]["added"]:
        focus.append({"surface": "protection", "reason": "Protection signals increased or changed; expect lower static-analysis visibility."})
    if recovery["obfuscation_delta"] > 0.1 or recovery["high_entropy_after"] > recovery["high_entropy_before"]:
        focus.append({"surface": "recovery", "reason": "Readability/protected-content signals increased in the newer build."})
    if base.get("manifest_changed"):
        focus.append({"surface": "manifest", "reason": "Android manifest fingerprint changed; review permissions/components in authorized source evidence."})

    change_score = len(changed_surfaces) + min(3, len(focus))
    if change_score >= 7:
        impact = "high"
    elif change_score >= 3:
        impact = "medium"
    elif change_score:
        impact = "low"
    else:
        impact = "none"

    return {
        "schema_version": "blc.reverselab.version-intelligence/v1",
        "before": {
            "sha256": before.get("sha256"),
            "target": before.get("target"),
            "file_type": before.get("file_type"),
        },
        "after": {
            "sha256": after.get("sha256"),
            "target": after.get("target"),
            "file_type": after.get("file_type"),
        },
        "impact": impact,
        "changed_surfaces": changed_surfaces,
        "analysis_reuse_ratio": float(base.get("analysis_reuse_ratio", 0.0)),
        "managed": managed,
        "jni": jni,
        "native": {
            "functions_before": int(base.get("native_functions_before", 0)),
            "functions_after": int(base.get("native_functions_after", 0)),
            "semantic_match_count": int(base.get("native_semantic_match_count", 0)),
            "reuse_ratio": float(base.get("native_function_reuse_ratio", 0.0)),
            "unmatched_before": int(base.get("native_unmatched_before", 0)),
            "unmatched_after": int(base.get("native_unmatched_after", 0)),
            "added_libraries": list(base.get("added_native") or []),
            "removed_libraries": list(base.get("removed_native") or []),
            "changed_libraries": list(base.get("changed_native") or []),
            "semantic_matches": list(base.get("native_semantic_matches") or [])[:250],
        },
        "protection": protection,
        "recovery": recovery,
        "android_structure": {
            "manifest_changed": bool(base.get("manifest_changed", False)),
            "resource_entry_delta": int(base.get("resource_entry_delta", 0)),
            "added_dex": list(base.get("added_dex") or []),
            "removed_dex": list(base.get("removed_dex") or []),
            "changed_dex": list(base.get("changed_dex") or []),
        },
        "evidence": {
            "added": list(base.get("evidence_added") or []),
            "removed": list(base.get("evidence_removed") or []),
        },
        "focus": focus,
        "base_diff": base,
        "caveat": "Differences reflect only evidence present in the two saved analyses; missing analyzer output is not proof that a surface is absent.",
    }
