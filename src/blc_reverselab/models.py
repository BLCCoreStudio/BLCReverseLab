from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "blc.reverselab.analysis/v1"


@dataclass(slots=True)
class Evidence:
    id: str
    kind: str
    summary: str
    source: str
    confidence: float = 1.0
    data: dict[str, Any] = field(default_factory=dict)
    related: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AnalysisContext:
    target: Path
    sha256: str = ""
    file_type: str = "unknown"
    facts: dict[str, Any] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    completed_steps: list[str] = field(default_factory=list)

    def add(self, evidence: Evidence) -> None:
        self.evidence.append(evidence)

    def to_dict(self) -> dict[str, Any]:
        from .graph import EvidenceGraph

        graph = EvidenceGraph.from_evidence(self.evidence)
        return {
            "schema_version": SCHEMA_VERSION,
            "target": str(self.target),
            "sha256": self.sha256,
            "file_type": self.file_type,
            "facts": self.facts,
            "evidence": [item.to_dict() for item in self.evidence],
            "evidence_graph": graph.to_dict(),
            "completed_steps": self.completed_steps,
        }
