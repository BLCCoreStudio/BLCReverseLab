from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


def _safe(value: Any) -> str:
    return str(value or "").strip()


def build_analysis_graph(report: dict[str, Any]) -> dict[str, Any]:
    """Build a conservative cross-layer navigation graph from proven report facts."""
    facts = dict(report.get("facts") or {})
    nodes: dict[str, dict[str, Any]] = {}
    edges: set[tuple[str, str, str]] = set()

    def add_node(node_id: str, *, layer: str, kind: str, label: str, data: dict[str, Any] | None = None) -> str:
        nodes.setdefault(
            node_id,
            {
                "id": node_id,
                "layer": layer,
                "kind": kind,
                "label": label,
                "data": dict(data or {}),
            },
        )
        return node_id

    def add_edge(source: str, target: str, relation: str) -> None:
        if source in nodes and target in nodes:
            edges.add((source, target, relation))

    managed = dict(facts.get("managed_index") or {})
    class_nodes: dict[str, str] = {}
    method_nodes: dict[tuple[str, str], list[str]] = defaultdict(list)

    for item in managed.get("classes", []) or []:
        if not isinstance(item, dict):
            continue
        name = _safe(item.get("name"))
        if not name:
            continue
        node_id = f"managed-class:{name}"
        class_nodes[name] = add_node(node_id, layer="managed", kind="class", label=name, data=item)

    for index, item in enumerate(managed.get("methods", []) or []):
        if not isinstance(item, dict):
            continue
        class_name = _safe(item.get("class_name"))
        method_name = _safe(item.get("name"))
        if not method_name:
            continue
        signature = f"{class_name}.{method_name}" if class_name else method_name
        node_id = f"managed-method:{signature}:{index}"
        add_node(node_id, layer="managed", kind="method", label=signature, data=item)
        method_nodes[(class_name, method_name)].append(node_id)
        if class_name in class_nodes:
            add_edge(class_nodes[class_name], node_id, "contains")

    endpoint_nodes: list[str] = []
    for endpoint in managed.get("endpoints", []) or []:
        value = _safe(endpoint)
        if not value:
            continue
        node_id = f"endpoint:{value}"
        endpoint_nodes.append(add_node(node_id, layer="network", kind="endpoint", label=value, data={"endpoint": value}))

    native_by_name: dict[str, list[str]] = defaultdict(list)
    for result_index, result in enumerate((facts.get("ghidra") or {}).get("results", []) or []):
        if not isinstance(result, dict):
            continue
        target = _safe(result.get("archive_member") or result.get("target"))
        for fn_index, item in enumerate(result.get("function_fingerprints", []) or []):
            if not isinstance(item, dict):
                continue
            name = _safe(item.get("name")) or "unnamed"
            address = _safe(item.get("address")) or str(fn_index)
            node_id = f"native-function:{target}:{address}:{fn_index}"
            label = f"{target}!{name}" if target else name
            add_node(node_id, layer="native", kind="function", label=label, data={"target": target, **item})
            native_by_name[name].append(node_id)

    jni = dict(facts.get("jni_crossrefs") or {})
    for index, item in enumerate(jni.get("declarations", []) or []):
        if not isinstance(item, dict):
            continue
        class_name = _safe(item.get("class_name"))
        method_name = _safe(item.get("method_name"))
        label = f"{class_name}.{method_name}" if class_name else method_name
        node_id = f"jni:{label}:{index}"
        add_node(node_id, layer="jni", kind="bridge", label=label, data=item)
        for managed_id in method_nodes.get((class_name, method_name), []):
            add_edge(managed_id, node_id, "declares-native")
        for match in item.get("matches", []) or []:
            match_name = _safe(match)
            for native_id in native_by_name.get(match_name, []):
                add_edge(node_id, native_id, "resolves-to")

    recovery = dict(facts.get("recovery") or {})
    for index, item in enumerate(recovery.get("recovered_literals", []) or []):
        if not isinstance(item, dict):
            continue
        preview = _safe(item.get("decoded_preview"))
        source = _safe(item.get("source_file"))
        node_id = f"recovered-literal:{source}:{index}"
        add_node(node_id, layer="recovery", kind="literal", label=preview or source or f"literal-{index}", data=item)

    evidence_lookup: dict[str, str] = {}
    for item in report.get("evidence", []) or []:
        if not isinstance(item, dict):
            continue
        evidence_id = _safe(item.get("id"))
        if not evidence_id:
            continue
        node_id = f"evidence:{evidence_id}"
        evidence_lookup[evidence_id] = add_node(
            node_id,
            layer="evidence",
            kind=_safe(item.get("kind")) or "evidence",
            label=_safe(item.get("summary")) or evidence_id,
            data=item,
        )

    evidence_graph = dict(report.get("evidence_graph") or {})
    for edge in evidence_graph.get("edges", []) or []:
        if not isinstance(edge, dict):
            continue
        source = evidence_lookup.get(_safe(edge.get("source")))
        target = evidence_lookup.get(_safe(edge.get("target")))
        if source and target:
            add_edge(source, target, _safe(edge.get("relation")) or "related")

    node_list = [nodes[key] for key in sorted(nodes)]
    edge_list = [
        {"source": source, "target": target, "relation": relation}
        for source, target, relation in sorted(edges)
    ]
    layer_counts = Counter(node["layer"] for node in node_list)
    kind_counts = Counter(node["kind"] for node in node_list)

    return {
        "schema_version": "blc.reverselab.analysis-graph/v1",
        "nodes": node_list,
        "edges": edge_list,
        "stats": {
            "node_count": len(node_list),
            "edge_count": len(edge_list),
            "layers": dict(sorted(layer_counts.items())),
            "kinds": dict(sorted(kind_counts.items())),
            "endpoint_count": len(endpoint_nodes),
        },
    }


def graph_to_dot(graph: dict[str, Any]) -> str:
    def quote(value: Any) -> str:
        return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'

    lines = ["digraph BLCReverseLab {", "  rankdir=LR;"]
    for node in graph.get("nodes", []) or []:
        if not isinstance(node, dict):
            continue
        label = f"{node.get('label', '')}\\n[{node.get('layer', '')}]"
        lines.append(f"  {quote(node.get('id', ''))} [label={quote(label)}];")
    for edge in graph.get("edges", []) or []:
        if not isinstance(edge, dict):
            continue
        lines.append(
            f"  {quote(edge.get('source', ''))} -> {quote(edge.get('target', ''))} "
            f"[label={quote(edge.get('relation', 'related'))}];"
        )
    lines.append("}")
    return "\n".join(lines) + "\n"
