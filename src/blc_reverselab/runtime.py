from __future__ import annotations

import copy
from typing import Any

_ALLOWED = ("jni_registrations", "observed_calls", "plaintext_observations", "loaded_modules")


def _graph(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    ids = {str(item.get("id")) for item in evidence if item.get("id")}
    edges: list[dict[str, str]] = []
    unresolved: set[str] = set()
    for item in evidence:
        source = str(item.get("id") or "")
        for target in item.get("related") or []:
            target = str(target)
            edges.append({"source": source, "target": target, "relation": "related"})
            if target not in ids:
                unresolved.add(target)
    return {
        "nodes": [{"id": str(item.get("id")), "kind": item.get("kind"), "source": item.get("source")} for item in evidence if item.get("id")],
        "edges": edges, "unresolved_targets": sorted(unresolved),
        "stats": {"node_count": len(ids), "edge_count": len(edges)},
    }


def enrich_with_runtime_observations(report: dict[str, Any], observations: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(report)
    facts = result.setdefault("facts", {})
    evidence = result.setdefault("evidence", [])
    normalized: dict[str, list[Any]] = {}
    counter = 0
    for category in _ALLOWED:
        values = observations.get(category) or []
        if not isinstance(values, list):
            raise ValueError(f"Runtime observation field must be a list: {category}")
        normalized[category] = list(values)
        for value in values[:250]:
            evidence.append({
                "id": f"ev:runtime:{counter}", "kind": "runtime-observation",
                "summary": f"Imported authorized runtime observation: {category}",
                "source": "authorized-runtime-import", "confidence": 1.0,
                "data": {"category": category, "value": value}, "related": ["ev:fingerprint"],
            })
            counter += 1
    facts["runtime_observations"] = {
        "schema_version": observations.get("schema_version", "blc.reverselab.runtime-observations/v1"),
        "counts": {key: len(value) for key, value in normalized.items()}, "observations": normalized,
    }
    completed = result.setdefault("completed_steps", [])
    if "runtime-observation-import" not in completed:
        completed.append("runtime-observation-import")
    result["evidence_graph"] = _graph(evidence)
    return result
