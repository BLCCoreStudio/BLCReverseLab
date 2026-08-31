from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)
_CLASS_RE = re.compile(r"\b(?:class|interface|enum)\s+([A-Za-z_$][\w$]*)")
_METHOD_RE = re.compile(r"\b(?:public|protected|private|static|final|synchronized|abstract|native|strictfp|\s)+\s*([\w.$<>\[\]?]+)\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_ROUTE_RE = re.compile(r'\"(/(?:api|v\d+|auth|user|users|account|game|match|inventory|store|profile|session)[^\"\s]{0,180})\"', re.IGNORECASE)


@dataclass(slots=True)
class ManagedClass:
    name: str
    source_file: str
    method_count: int
    native_method_count: int

    def to_dict(self) -> dict[str, Any]: return asdict(self)


@dataclass(slots=True)
class ManagedMethod:
    class_name: str
    name: str
    return_type: str
    parameters: str
    native: bool
    source_file: str

    def to_dict(self) -> dict[str, Any]: return asdict(self)


@dataclass(slots=True)
class ManagedIndexReport:
    status: str
    class_count: int = 0
    method_count: int = 0
    native_method_count: int = 0
    endpoint_count: int = 0
    classes: list[ManagedClass] = field(default_factory=list)
    methods: list[ManagedMethod] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "class_count": self.class_count, "method_count": self.method_count,
                "native_method_count": self.native_method_count, "endpoint_count": self.endpoint_count,
                "classes": [x.to_dict() for x in self.classes], "methods": [x.to_dict() for x in self.methods],
                "endpoints": list(self.endpoints)}


class ManagedIndexer:
    def analyze(self, source_root: str | Path | None, *, max_classes: int = 4000, max_methods: int = 12000, max_endpoints: int = 1000) -> ManagedIndexReport:
        if source_root is None: return ManagedIndexReport(status="no-decompiler-output")
        root = Path(source_root)
        if not root.is_dir(): return ManagedIndexReport(status="no-decompiler-output")
        classes: list[ManagedClass] = []; methods: list[ManagedMethod] = []; endpoints: set[str] = set()
        total_classes = total_methods = native_methods = 0
        for path in sorted(root.rglob("*.java")):
            try: text = path.read_text(encoding="utf-8", errors="replace")
            except OSError: continue
            pkg_match = _PACKAGE_RE.search(text); package = pkg_match.group(1) if pkg_match else ""
            class_match = _CLASS_RE.search(text); short = class_match.group(1) if class_match else path.stem
            fqcn = f"{package}.{short}" if package else short
            file_methods = 0; file_native = 0
            for match in _METHOD_RE.finditer(text):
                total_methods += 1; file_methods += 1
                prefix_start = max(0, match.start() - 120); prefix = text[prefix_start:match.start()]
                is_native = "native" in prefix.split()
                if is_native: native_methods += 1; file_native += 1
                if len(methods) < max_methods:
                    methods.append(ManagedMethod(fqcn, match.group(2), match.group(1), (match.group(3) or "").strip(), is_native, str(path.relative_to(root))))
            total_classes += 1
            if len(classes) < max_classes: classes.append(ManagedClass(fqcn, str(path.relative_to(root)), file_methods, file_native))
            if len(endpoints) < max_endpoints:
                endpoints.update(_URL_RE.findall(text)[:100])
                endpoints.update(m.group(1) for m in _ROUTE_RE.finditer(text))
        endpoints_list = sorted(endpoints)[:max_endpoints]
        return ManagedIndexReport("completed", total_classes, total_methods, native_methods, len(endpoints_list), classes, methods, endpoints_list)


@dataclass(slots=True)
class ManagedIndexStep:
    name: str = "managed-index"
    def run(self, ctx: "AnalysisContext") -> None:
        from .models import Evidence
        jadx = dict(ctx.facts.get("jadx") or {}); report = ManagedIndexer().analyze(jadx.get("output_dir")); ctx.facts["managed_index"] = report.to_dict()
        related = ["ev:jadx"] if any(item.id == "ev:jadx" for item in ctx.evidence) else ["ev:fingerprint"]
        ctx.add(Evidence(id="ev:managed-index", kind="managed-index", summary=f"Indexed {report.class_count} managed classes and {report.method_count} methods", source=self.name, related=related, confidence=0.92, data={"status": report.status, "class_count": report.class_count, "method_count": report.method_count, "native_method_count": report.native_method_count, "endpoint_count": report.endpoint_count}))
        if report.endpoints:
            ctx.add(Evidence(id="ev:endpoints", kind="network-surface", summary=f"Indexed {report.endpoint_count} static endpoint candidates", source=self.name, related=["ev:managed-index"], confidence=0.8, data={"endpoints": report.endpoints[:250]}))
