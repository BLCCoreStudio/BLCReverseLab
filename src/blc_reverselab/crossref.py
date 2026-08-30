from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)
_CLASS_RE = re.compile(r"\b(?:class|interface|enum)\s+([A-Za-z_$][\w$]*)")
_NATIVE_RE = re.compile(
    r"(?P<prefix>(?:(?:public|protected|private|static|final|synchronized|abstract|native|strictfp)\s+)*)"
    r"(?P<rtype>[\w.$<>\[\]?]+)\s+"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)\s*;",
    re.MULTILINE,
)


def _jni_escape(value: str) -> str:
    out: list[str] = []
    for char in value:
        if char == "_":
            out.append("_1")
        elif char == ";":
            out.append("_2")
        elif char == "[":
            out.append("_3")
        elif char in {"/", "."}:
            out.append("_")
        elif char.isalnum():
            out.append(char)
        else:
            out.append(f"_0{ord(char):04x}")
    return "".join(out)


@dataclass(slots=True)
class JavaNativeDeclaration:
    source_file: str
    class_name: str
    method_name: str
    return_type: str
    parameters: str
    expected_jni_symbol: str
    matches: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CrossReferenceReport:
    status: str
    declaration_count: int = 0
    matched_declaration_count: int = 0
    unresolved_declaration_count: int = 0
    dynamic_registration_signal: bool = False
    declarations: list[JavaNativeDeclaration] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["declarations"] = [item.to_dict() for item in self.declarations]
        return payload


class JniCrossReferenceAnalyzer:
    def analyze(
        self,
        source_root: str | Path | None,
        ghidra_report: dict[str, Any] | None,
        *,
        max_declarations: int = 2000,
    ) -> CrossReferenceReport:
        if source_root is None:
            return CrossReferenceReport(status="no-decompiler-output")

        root = Path(source_root)
        if not root.is_dir():
            return CrossReferenceReport(status="no-decompiler-output")

        ghidra = dict(ghidra_report or {})
        candidates = {
            str(item)
            for item in (ghidra.get("jni_candidates") or [])
            if item
        }
        dynamic_registration = "JNI_OnLoad" in candidates
        for result in ghidra.get("results") or []:
            for function in result.get("function_sample") or []:
                name = str(function.get("name") or "")
                if "RegisterNatives" in name:
                    dynamic_registration = True

        declarations: list[JavaNativeDeclaration] = []
        for path in sorted(root.rglob("*.java")):
            if len(declarations) >= max_declarations:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            package_match = _PACKAGE_RE.search(text)
            package = package_match.group(1) if package_match else ""
            class_match = _CLASS_RE.search(text)
            class_name = class_match.group(1) if class_match else path.stem
            binary_class = f"{package}.{class_name}" if package else class_name

            for match in _NATIVE_RE.finditer(text):
                prefix = match.group("prefix") or ""
                if "native" not in prefix.split():
                    continue
                method_name = match.group("name")
                expected = f"Java_{_jni_escape(binary_class)}_{_jni_escape(method_name)}"
                matched = sorted(
                    item
                    for item in candidates
                    if item == expected or item.startswith(expected + "__")
                )
                declarations.append(
                    JavaNativeDeclaration(
                        source_file=str(path.relative_to(root)),
                        class_name=binary_class,
                        method_name=method_name,
                        return_type=match.group("rtype"),
                        parameters=(match.group("params") or "").strip(),
                        expected_jni_symbol=expected,
                        matches=matched,
                    )
                )
                if len(declarations) >= max_declarations:
                    break

        matched_count = sum(1 for item in declarations if item.matches)
        status = "completed" if declarations or candidates else "no-jni-surface"
        return CrossReferenceReport(
            status=status,
            declaration_count=len(declarations),
            matched_declaration_count=matched_count,
            unresolved_declaration_count=len(declarations) - matched_count,
            dynamic_registration_signal=dynamic_registration,
            declarations=declarations,
        )


@dataclass(slots=True)
class JniCrossReferenceStep:
    name: str = "jni-crossrefs"

    def run(self, ctx: "AnalysisContext") -> None:
        from .models import Evidence

        jadx = dict(ctx.facts.get("jadx") or {})
        report = JniCrossReferenceAnalyzer().analyze(
            jadx.get("output_dir"),
            dict(ctx.facts.get("ghidra") or {}),
        )
        payload = report.to_dict()
        ctx.facts["jni_crossrefs"] = payload
        related = []
        existing = {item.id for item in ctx.evidence}
        if "ev:jadx" in existing:
            related.append("ev:jadx")
        if "ev:ghidra" in existing:
            related.append("ev:ghidra")
        if not related:
            related = ["ev:fingerprint"]
        ctx.add(
            Evidence(
                id="ev:jni-crossrefs",
                kind="cross-reference",
                summary=f"JNI cross-reference status: {report.status}",
                source=self.name,
                related=related,
                confidence=0.95,
                data={
                    "status": report.status,
                    "declaration_count": report.declaration_count,
                    "matched_declaration_count": report.matched_declaration_count,
                    "unresolved_declaration_count": report.unresolved_declaration_count,
                    "dynamic_registration_signal": report.dynamic_registration_signal,
                },
            )
        )
        for index, item in enumerate(report.declarations[:250]):
            if not item.matches:
                continue
            ctx.add(
                Evidence(
                    id=f"ev:jni-link:{index}",
                    kind="jni-link",
                    summary=f"Linked {item.class_name}.{item.method_name} to native JNI export",
                    source=self.name,
                    related=["ev:jni-crossrefs"],
                    confidence=0.98,
                    data=item.to_dict(),
                )
            )
