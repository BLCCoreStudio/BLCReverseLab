from blc_reverselab.graph import EvidenceGraph
from blc_reverselab.models import Evidence


def test_evidence_graph_links_and_queries():
    graph = EvidenceGraph.from_evidence(
        [
            Evidence(id="ev:a", kind="artifact", summary="artifact", source="fingerprint"),
            Evidence(
                id="ev:b",
                kind="structure",
                summary="structure",
                source="archive",
                confidence=0.9,
                related=["ev:a"],
            ),
        ]
    )

    assert graph.neighbors("ev:a") == ["ev:b"]
    assert [node["id"] for node in graph.query(kind="structure")] == ["ev:b"]
    payload = graph.to_dict()
    assert payload["stats"]["node_count"] == 2
    assert payload["stats"]["edge_count"] == 1
    assert payload["unresolved_targets"] == []
