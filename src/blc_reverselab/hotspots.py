from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_BRANCH_RE = re.compile(r"\b(?:if|for|while|switch|catch)\s*\(")


@dataclass(slots=True)
class Hotspot:
    source_file: str
    reason: str
    score: float
    line_count: int
    branch_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class HotspotReport:
    status: str
    java_file_count: int = 0
    decompiler_warning_count: int = 0
    not_decompiled_count: int = 0
    hotspot_count: int = 0
    hotspots: list[Hotspot] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["hotspots"] = [item.to_dict() for item in self.hotspots]
        return payload


class DecompilerHotspotAnalyzer:
    def analyze(self, source_root: str | Path | None, *, max_hotspots: int = 100) -> HotspotReport:
        if source_root is None:
            return HotspotReport(status="no-decompiler-output")
        root = Path(source_root)
        if not root.is_dir():
            return HotspotReport(status="no-decompiler-output")
        java_files = sorted(path for path in root.rglob("*.java") if path.is_file())
        hotspots: list[Hotspot] = []
        warnings = 0
        not_decompiled = 0
        for path in java_files:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            warnings += text.count("/* JADX") + text.count("JADX WARN") + text.count("JADX ERROR")
            not_decompiled += text.count("Method not decompiled")
            line_count = max(1, text.count("\n") + 1)
            branch_count = len(_BRANCH_RE.findall(text))
            density = branch_count / line_count
            reasons: list[str] = []
            score = 0.0
            if line_count >= 3000:
                reasons.append("very-large-decompiled-file"); score += 0.35
            if branch_count >= 80:
                reasons.append("high-control-flow-count"); score += 0.35
            if line_count >= 200 and density >= 0.12:
                reasons.append("high-branch-density"); score += 0.3
            if "Method not decompiled" in text:
                reasons.append("decompiler-failure"); score = 1.0
            if reasons and len(hotspots) < max_hotspots:
                hotspots.append(Hotspot(str(path.relative_to(root)), ",".join(reasons), round(min(1.0, score), 3), line_count, branch_count))
        hotspots.sort(key=lambda item: (-item.score, -item.branch_count, item.source_file))
        return HotspotReport("completed", len(java_files), warnings, not_decompiled, len(hotspots), hotspots)


@dataclass(slots=True)
class HotspotStep:
    name: str = "decompiler-hotspots"

    def run(self, ctx: "AnalysisContext") -> None:
        from .models import Evidence
        jadx = dict(ctx.facts.get("jadx") or {})
        report = DecompilerHotspotAnalyzer().analyze(jadx.get("output_dir"))
        ctx.facts["decompiler_hotspots"] = report.to_dict()
        related = ["ev:jadx"] if any(item.id == "ev:jadx" for item in ctx.evidence) else ["ev:fingerprint"]
        ctx.add(Evidence(
            id="ev:decompiler-hotspots", kind="analysis-hotspots",
            summary=f"Decompiler hotspot scan: {report.hotspot_count} hotspots", source=self.name,
            related=related, confidence=0.9,
            data={"status": report.status, "java_file_count": report.java_file_count,
                  "decompiler_warning_count": report.decompiler_warning_count,
                  "not_decompiled_count": report.not_decompiled_count,
                  "hotspot_count": report.hotspot_count,
                  "hotspots": [item.to_dict() for item in report.hotspots[:50]]},
        ))
