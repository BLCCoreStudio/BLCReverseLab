from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .adapters import JadxAdapter
from .models import AnalysisContext, Evidence
from .recovery import RecoveryAnalyzer


class Step(Protocol):
    name: str

    def run(self, ctx: AnalysisContext) -> None: ...


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _tracked_kind(name: str) -> str | None:
    lower = name.lower()
    if lower.endswith(".dex"):
        return "dex"
    if lower.endswith(".so"):
        return "native"
    if lower.endswith("androidmanifest.xml"):
        return "manifest"
    if lower.endswith("resources.arsc"):
        return "resources-table"
    if lower.endswith("global-metadata.dat"):
        return "unity-metadata"
    return None


@dataclass(slots=True)
class FingerprintStep:
    name: str = "fingerprint"

    def run(self, ctx: AnalysisContext) -> None:
        ctx.sha256 = _sha256(ctx.target)
        suffix = ctx.target.suffix.lower()
        if suffix in {".apk", ".aab", ".apks", ".xapk"}:
            ctx.file_type = suffix[1:]
        elif suffix in {".dex", ".so", ".exe", ".dll"}:
            ctx.file_type = suffix[1:]
        else:
            ctx.file_type = "binary"
        ctx.add(
            Evidence(
                id="ev:fingerprint",
                kind="artifact",
                summary=f"Identified {ctx.file_type} artifact",
                source=self.name,
                data={"sha256": ctx.sha256, "size": ctx.target.stat().st_size},
            )
        )


@dataclass(slots=True)
class AndroidArchiveStep:
    name: str = "android-archive"

    def run(self, ctx: AnalysisContext) -> None:
        if ctx.file_type not in {"apk", "aab", "apks", "xapk"}:
            return
        if not zipfile.is_zipfile(ctx.target):
            ctx.add(
                Evidence(
                    id="ev:archive-invalid",
                    kind="warning",
                    summary="Android container is not a readable ZIP archive",
                    source=self.name,
                    confidence=1.0,
                    related=["ev:fingerprint"],
                )
            )
            return

        with zipfile.ZipFile(ctx.target) as zf:
            infos = zf.infolist()

        names = [info.filename for info in infos]
        dex = sorted(n for n in names if n.lower().endswith(".dex"))
        native = sorted(n for n in names if n.lower().endswith(".so"))
        manifests = sorted(n for n in names if n.lower().endswith("androidmanifest.xml"))
        resources = [n for n in names if n.startswith("res/") or "/res/" in n]

        tracked_entries: dict[str, dict[str, object]] = {}
        for info in infos:
            kind = _tracked_kind(info.filename)
            if not kind:
                continue
            tracked_entries[info.filename] = {
                "kind": kind,
                "crc32": f"{info.CRC:08x}",
                "size": info.file_size,
                "compressed_size": info.compress_size,
            }

        engines: list[str] = []
        lower = [n.lower() for n in names]
        if any("libil2cpp.so" in n for n in lower):
            engines.append("unity-il2cpp")
        if any("libunity.so" in n for n in lower) and "unity-il2cpp" not in engines:
            engines.append("unity")
        if any("libue4.so" in n or "libunreal.so" in n for n in lower):
            engines.append("unreal")

        ctx.facts.update(
            {
                "dex_files": dex,
                "native_libraries": native,
                "manifest_entries": manifests,
                "resource_entry_count": len(resources),
                "detected_engines": engines,
                "tracked_entries": tracked_entries,
            }
        )
        ctx.add(
            Evidence(
                id="ev:android-structure",
                kind="structure",
                summary="Mapped Android package structure",
                source=self.name,
                related=["ev:fingerprint"],
                data={
                    "dex_count": len(dex),
                    "native_count": len(native),
                    "manifest_count": len(manifests),
                    "resource_entries": len(resources),
                    "tracked_entry_count": len(tracked_entries),
                    "engines": engines,
                },
            )
        )

        for name, record in sorted(tracked_entries.items()):
            ctx.add(
                Evidence(
                    id=f"ev:entry:{name}",
                    kind="archive-entry",
                    summary=f"Tracked {record['kind']} entry {name}",
                    source=self.name,
                    related=["ev:android-structure"],
                    data=dict(record),
                )
            )

        for engine in engines:
            related = [
                f"ev:entry:{name}"
                for name in tracked_entries
                if (
                    engine.startswith("unity")
                    and (
                        "libunity.so" in name.lower()
                        or "libil2cpp.so" in name.lower()
                        or "global-metadata.dat" in name.lower()
                    )
                )
                or (engine == "unreal" and ("libue4.so" in name.lower() or "libunreal.so" in name.lower()))
            ]
            ctx.add(
                Evidence(
                    id=f"ev:engine:{engine}",
                    kind="engine-fingerprint",
                    summary=f"Detected {engine} fingerprint",
                    source=self.name,
                    confidence=0.95,
                    related=sorted(related),
                    data={"engine": engine},
                )
            )


@dataclass(slots=True)
class ToolReadinessStep:
    name: str = "tool-readiness"

    def run(self, ctx: AnalysisContext) -> None:
        tool_names = ("jadx", "jadx-gui", "ghidraRun", "analyzeHeadless")
        paths = {name: shutil.which(name) for name in tool_names}
        ctx.facts["tools"] = {name: bool(path) for name, path in paths.items()}
        ctx.facts["tool_paths"] = paths
        ctx.add(
            Evidence(
                id="ev:tool-readiness",
                kind="environment",
                summary="Checked optional analysis adapters",
                source=self.name,
                related=["ev:fingerprint"],
                data=ctx.facts["tools"],
            )
        )


@dataclass(slots=True)
class JadxStep:
    output_root: Path
    timeout_seconds: int = 180
    deobfuscate: bool = False
    mappings_path: Path | None = None
    name: str = "jadx"

    def run(self, ctx: AnalysisContext) -> None:
        if ctx.file_type not in {"apk", "aab", "xapk", "dex"}:
            return
        destination = self.output_root / ctx.sha256[:16]
        result = JadxAdapter(
            timeout_seconds=self.timeout_seconds,
            deobfuscate=self.deobfuscate,
            mappings_path=self.mappings_path,
        ).analyze(ctx.target, destination)
        ctx.facts["jadx"] = result.to_dict()
        existing_ids = {item.id for item in ctx.evidence}
        related = ["ev:fingerprint"]
        if "ev:android-structure" in existing_ids:
            related.append("ev:android-structure")
        ctx.add(
            Evidence(
                id="ev:jadx",
                kind="adapter-result",
                summary=f"JADX adapter status: {result.status}",
                source=self.name,
                related=related,
                confidence=1.0,
                data={
                    "available": result.available,
                    "status": result.status,
                    "return_code": result.return_code,
                    "java_file_count": result.java_file_count,
                    "resource_file_count": result.resource_file_count,
                    "output_dir": result.output_dir,
                    "deobfuscation_requested": result.deobfuscation_requested,
                    "mappings_path": result.mappings_path,
                },
            )
        )


@dataclass(slots=True)
class RecoveryStep:
    name: str = "recovery"

    def run(self, ctx: AnalysisContext) -> None:
        jadx = dict(ctx.facts.get("jadx") or {})
        report = RecoveryAnalyzer().analyze(jadx.get("output_dir"))
        ctx.facts["recovery"] = report.to_dict()
        ctx.add(
            Evidence(
                id="ev:recovery",
                kind="recovery-profile",
                summary=f"Recovery pipeline status: {report.status}",
                source=self.name,
                related=["ev:jadx"],
                confidence=0.9 if report.status == "completed" else 1.0,
                data={
                    "status": report.status,
                    "obfuscation_score": report.obfuscation_score,
                    "suspicious_identifier_count": report.suspicious_identifier_count,
                    "encoded_literal_candidates": report.encoded_literal_candidates,
                    "recovered_literal_count": report.recovered_literal_count,
                    "high_entropy_literal_count": report.high_entropy_literal_count,
                    "capabilities": report.capabilities,
                },
            )
        )

        for index, item in enumerate(report.recovered_literals):
            ctx.add(
                Evidence(
                    id=f"ev:recovered-literal:{index}",
                    kind="recovered-literal",
                    summary=f"Recovered reversible {item.encoding} literal",
                    source=self.name,
                    related=["ev:recovery"],
                    confidence=0.98,
                    data=item.to_dict(),
                )
            )


class Pipeline:
    def __init__(
        self,
        steps: list[Step] | None = None,
        *,
        enable_jadx: bool = False,
        enable_recovery: bool = False,
        mappings_path: str | Path | None = None,
        workdir: str | Path = ".blc-reverselab",
    ) -> None:
        if steps is not None:
            self.steps = steps
            return

        mapping = Path(mappings_path).expanduser() if mappings_path else None
        built: list[Step] = [FingerprintStep(), AndroidArchiveStep(), ToolReadinessStep()]
        if enable_jadx or enable_recovery:
            built.append(
                JadxStep(
                    Path(workdir),
                    deobfuscate=enable_recovery,
                    mappings_path=mapping,
                )
            )
        if enable_recovery:
            built.append(RecoveryStep())
        self.steps = built

    def analyze(self, target: str | Path) -> AnalysisContext:
        path = Path(target).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(path)
        ctx = AnalysisContext(target=path)
        for step in self.steps:
            step.run(ctx)
            ctx.completed_steps.append(step.name)
        return ctx

    @staticmethod
    def save(ctx: AnalysisContext, output: str | Path) -> Path:
        out = Path(output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(ctx.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        return out
