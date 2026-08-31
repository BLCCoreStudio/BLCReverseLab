from __future__ import annotations

from typing import Any

from .query import search_report

_KIND_LAYER = {
    "managed-class": "managed",
    "managed-method": "managed",
    "jni-link": "jni",
    "native-function": "native",
    "endpoint": "network",
    "recovered-literal": "recovery",
    "evidence": "evidence",
}


def ask_report(report: dict[str, Any], question: str, *, limit: int = 8) -> dict[str, Any]:
    """Answer a question only from evidence already present in a ReverseLab report.

    This is intentionally deterministic and offline.  It is also the stable grounding
    contract that optional model-backed analyst plugins can consume later.
    """
    question = question.strip()
    if not question:
        raise ValueError("question must not be empty")

    search = search_report(report, question, limit=max(25, limit * 4))
    hits = list(search.get("results") or [])
    selected = hits[: max(1, limit)]

    if not selected:
        return {
            "schema_version": "blc.reverselab.analyst/v1",
            "question": question,
            "status": "insufficient-evidence",
            "confidence": 0.0,
            "answer": "No evidence-backed match was found in this analysis. Run deeper analysis or provide additional authorized evidence.",
            "layers": [],
            "support": [],
            "caveat": "ReverseLab does not invent missing source names, plaintext, call paths, or runtime behavior.",
        }

    layers = sorted({_KIND_LAYER.get(str(item.get("kind", "")), "other") for item in selected})
    top = selected[0]
    top_score = float(top.get("score") or 0.0)
    coverage = min(1.0, len(layers) / 4.0)
    confidence = round(min(0.99, 0.35 + (0.5 * top_score) + (0.14 * coverage)), 3)

    support = []
    for item in selected:
        data = dict(item.get("data") or {})
        evidence_id = data.get("id") if item.get("kind") == "evidence" else None
        support.append(
            {
                "kind": str(item.get("kind", "unknown")),
                "layer": _KIND_LAYER.get(str(item.get("kind", "")), "other"),
                "label": str(item.get("label", "")),
                "score": float(item.get("score") or 0.0),
                "evidence_id": evidence_id,
                "data": data,
            }
        )

    layer_text = ", ".join(layers)
    answer = (
        f"Found {len(selected)} evidence-backed match(es) across {layer_text}. "
        f"Strongest match: {top.get('label', '')} [{top.get('kind', 'unknown')}]."
    )
    if "jni" in layers and "native" in layers:
        answer += " Managed/JNI/native evidence is present, so the cross-layer path can be inspected without guessing missing links."
    elif "native" in layers:
        answer += " Native-code evidence is present; original symbol names may still be unavailable when the binary was stripped."
    if "recovery" in layers:
        answer += " Recovery evidence is present, but reversible decoding is not equivalent to breaking cryptographic encryption."

    return {
        "schema_version": "blc.reverselab.analyst/v1",
        "question": question,
        "status": "grounded",
        "confidence": confidence,
        "answer": answer,
        "layers": layers,
        "support": support,
        "caveat": "Conclusions are limited to evidence in the supplied analysis; inferred original source details are never presented as recovered facts.",
    }
