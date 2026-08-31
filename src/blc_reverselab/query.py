from __future__ import annotations

from typing import Any


def _score(text: str, tokens: list[str]) -> float:
    lower = text.lower()
    if not tokens: return 0.0
    hits = sum(1 for token in tokens if token in lower)
    return hits / len(tokens)


def search_report(report: dict[str, Any], query: str, *, limit: int = 100) -> dict[str, Any]:
    tokens = [item.lower() for item in query.split() if item.strip()]
    facts = dict(report.get("facts") or {})
    hits: list[dict[str, Any]] = []

    def add(kind: str, label: str, data: dict[str, Any]) -> None:
        score = _score(label, tokens)
        if score > 0: hits.append({"kind": kind, "label": label, "score": round(score, 3), "data": data})

    for item in facts.get("managed_index", {}).get("classes", []) or []:
        add("managed-class", str(item.get("name", "")), dict(item))
    for item in facts.get("managed_index", {}).get("methods", []) or []:
        label = f"{item.get('class_name','')}.{item.get('name','')} {item.get('return_type','')} {item.get('parameters','')}"
        add("managed-method", label, dict(item))
    for endpoint in facts.get("managed_index", {}).get("endpoints", []) or []:
        add("endpoint", str(endpoint), {"endpoint": endpoint})
    for result in facts.get("ghidra", {}).get("results", []) or []:
        target = str(result.get("archive_member") or result.get("target") or "")
        for item in result.get("function_fingerprints", []) or []:
            label = f"{target} {item.get('name','')} {item.get('address','')} {item.get('shape_id','')}"
            add("native-function", label, {"target": target, **dict(item)})
    for item in report.get("evidence", []) or []:
        if not isinstance(item, dict): continue
        label = " ".join(str(item.get(k, "")) for k in ("id", "kind", "source", "summary"))
        add("evidence", label, dict(item))
    for item in facts.get("jni_crossrefs", {}).get("declarations", []) or []:
        label = f"{item.get('class_name','')}.{item.get('method_name','')} {' '.join(item.get('matches') or [])}"
        add("jni-link", label, dict(item))
    for item in facts.get("recovery", {}).get("recovered_literals", []) or []:
        label = f"{item.get('source_file','')} {item.get('decoded_preview','')} {item.get('encoding','')}"
        add("recovered-literal", label, dict(item))

    hits.sort(key=lambda item: (-item["score"], item["kind"], item["label"]))
    return {"schema_version": "blc.reverselab.search/v1", "query": query, "result_count": min(len(hits), limit), "results": hits[:limit]}
