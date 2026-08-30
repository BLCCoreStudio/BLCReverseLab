from __future__ import annotations

import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ProtectionSignal:
    category: str
    name: str
    confidence: float
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ProtectionReport:
    status: str
    level: str
    score: float
    signals: list[ProtectionSignal] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["signals"] = [item.to_dict() for item in self.signals]
        return payload


class ProtectionAnalyzer:
    _FINGERPRINTS = {
        "jiagu-like": ("libjiagu.so", "libjiagu_art.so"),
        "secneo-like": ("libdexhelper.so", "libdexhelper-x86.so", "libsecmain.so"),
        "bangcle-like": ("libsecexe.so", "libsecmain.so"),
        "ijiami-like": ("libexec.so", "ijiami"),
        "dex-protector-like": ("dexprotector", "libdpboot.so"),
    }

    def analyze(self, target: Path, facts: dict[str, Any]) -> ProtectionReport:
        signals: list[ProtectionSignal] = []
        names: list[str] = []
        if zipfile.is_zipfile(target):
            try:
                with zipfile.ZipFile(target) as zf:
                    names = [item.filename.lower() for item in zf.infolist()]
            except OSError:
                names = []

        for label, tokens in self._FINGERPRINTS.items():
            matched = sorted(
                {
                    name
                    for name in names
                    if any(token in name for token in tokens)
                }
            )
            if matched:
                signals.append(
                    ProtectionSignal(
                        category="protector-fingerprint",
                        name=label,
                        confidence=0.9,
                        evidence=matched[:20],
                    )
                )

        recovery = dict(facts.get("recovery") or {})
        obfuscation_score = float(recovery.get("obfuscation_score", 0.0))
        if obfuscation_score >= 0.35:
            signals.append(
                ProtectionSignal(
                    category="obfuscation",
                    name="high-obfuscation" if obfuscation_score >= 0.7 else "moderate-obfuscation",
                    confidence=min(0.98, 0.65 + obfuscation_score * 0.3),
                    evidence=[f"obfuscation_score={obfuscation_score:.3f}"],
                )
            )

        high_entropy = int(recovery.get("high_entropy_literal_count", 0))
        recovered = int(recovery.get("recovered_literal_count", 0))
        if high_entropy > recovered:
            signals.append(
                ProtectionSignal(
                    category="protected-content",
                    name="unresolved-high-entropy-literals",
                    confidence=0.72,
                    evidence=[f"high_entropy={high_entropy}", f"recovered={recovered}"],
                )
            )

        ghidra = dict(facts.get("ghidra") or {})
        generic_ratio = float(ghidra.get("generic_function_ratio", 0.0))
        function_count = int(ghidra.get("function_count", 0))
        if function_count and generic_ratio >= 0.6:
            signals.append(
                ProtectionSignal(
                    category="native-symbols",
                    name="heavily-stripped-native-surface",
                    confidence=0.8,
                    evidence=[
                        f"generic_function_ratio={generic_ratio:.4f}",
                        f"function_count={function_count}",
                    ],
                )
            )

        weighted = sum(item.confidence for item in signals)
        score = min(1.0, weighted / 3.0)
        if score >= 0.7:
            level = "high"
        elif score >= 0.35:
            level = "medium"
        elif signals:
            level = "low"
        else:
            level = "none"

        return ProtectionReport(
            status="completed",
            level=level,
            score=round(score, 3),
            signals=signals,
        )


@dataclass(slots=True)
class ProtectionStep:
    name: str = "protection-profile"

    def run(self, ctx: "AnalysisContext") -> None:
        from .models import Evidence

        report = ProtectionAnalyzer().analyze(ctx.target, ctx.facts)
        ctx.facts["protection"] = report.to_dict()
        related = ["ev:fingerprint"]
        existing = {item.id for item in ctx.evidence}
        for candidate in ("ev:recovery", "ev:ghidra", "ev:android-structure"):
            if candidate in existing:
                related.append(candidate)
        ctx.add(
            Evidence(
                id="ev:protection",
                kind="protection-profile",
                summary=f"Protection profile: {report.level}",
                source=self.name,
                related=related,
                confidence=0.9,
                data={
                    "status": report.status,
                    "level": report.level,
                    "score": report.score,
                    "signal_count": len(report.signals),
                    "signals": [item.to_dict() for item in report.signals],
                },
            )
        )
