from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, Iterable

if TYPE_CHECKING:
    from .models import Evidence


@dataclass(frozen=True, slots=True)
class GraphEdge:
    source: str
    target: str
    relation: str = "related"

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(slots=True)
class EvidenceGraph:
    nodes: dict[str, dict[str, Any]]
    edges: list[GraphEdge]
    unresolved_targets: list[str]

    @classmethod
    def from_evidence(cls, evidence: Iterable["Evidence"]) -> "EvidenceGraph":
        items = list(evidence)
        known = {item.id for item in items}
        nodes = {
            item.id: {
                "id": item.id,
                "kind": item.kind,
                "summary": item.summary,
                "source": item.source,
                "confidence": item.confidence,
                "data": item.data,
            }
            for item in items
        }
        edges: list[GraphEdge] = []
        unresolved: set[str] = set()
        for item in items:
            for target in item.related:
                edges.append(GraphEdge(source=item.id, target=target))
                if target not in known:
                    unresolved.add(target)
        edges.sort(key=lambda edge: (edge.source, edge.target, edge.relation))
        return cls(nodes=nodes, edges=edges, unresolved_targets=sorted(unresolved))

    def neighbors(self, evidence_id: str) -> list[str]:
        linked: set[str] = set()
        for edge in self.edges:
            if edge.source == evidence_id:
                linked.add(edge.target)
            if edge.target == evidence_id:
                linked.add(edge.source)
        return sorted(linked)

    def query(
        self,
        *,
        kind: str | None = None,
        source: str | None = None,
        min_confidence: float = 0.0,
    ) -> list[dict[str, Any]]:
        results = []
        for node in self.nodes.values():
            if kind is not None and node["kind"] != kind:
                continue
            if source is not None and node["source"] != source:
                continue
            if float(node["confidence"]) < min_confidence:
                continue
            results.append(node)
        return sorted(results, key=lambda node: node["id"])

    def to_dict(self) -> dict[str, Any]:
        kinds = Counter(str(node["kind"]) for node in self.nodes.values())
        sources = Counter(str(node["source"]) for node in self.nodes.values())
        return {
            "nodes": [self.nodes[key] for key in sorted(self.nodes)],
            "edges": [edge.to_dict() for edge in self.edges],
            "unresolved_targets": self.unresolved_targets,
            "stats": {
                "node_count": len(self.nodes),
                "edge_count": len(self.edges),
                "kinds": dict(sorted(kinds.items())),
                "sources": dict(sorted(sources.items())),
            },
        }
