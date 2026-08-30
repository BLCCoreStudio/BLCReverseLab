from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .models import AnalysisContext, Evidence


class Step(Protocol):
    name: str
    def run(self, ctx: AnalysisContext) -> None: ...


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


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
        ctx.add(Evidence(
            id="ev:fingerprint",
            kind="artifact",
            summary=f"Identified {ctx.file_type} artifact",
            source=self.name,
            data={"sha256": ctx.sha256, "size": ctx.target.stat().st_size},
        ))


@dataclass(slots=True)
class AndroidArchiveStep:
    name: str = "android-archive"

    def run(self, ctx: AnalysisContext) -> None:
        if ctx.file_type not in {"apk", "aab", "apks", "xapk"}:
            return
        if not zipfile.is_zipfile(ctx.target):
            ctx.add(Evidence(
                id="ev:archive-invalid",
                kind="warning",
                summary="Android container is not a readable ZIP archive",
                source=self.name,
                confidence=1.0,
            ))
            return

        with zipfile.ZipFile(ctx.target) as zf:
            names = zf.namelist()
        dex = sorted(n for n in names if n.endswith(".dex"))
        native = sorted(n for n in names if n.endswith(".so"))
        manifests = sorted(n for n in names if n.endswith("AndroidManifest.xml"))
        resources = [n for n in names if n.startswith("res/") or "/res/" in n]

        engines: list[str] = []
        lower = [n.lower() for n in names]
        if any("libil2cpp.so" in n for n in lower):
            engines.append("unity-il2cpp")
        if any("libunity.so" in n for n in lower) and "unity-il2cpp" not in engines:
            engines.append("unity")
        if any("libue4.so" in n or "libunreal.so" in n for n in lower):
            engines.append("unreal")

        ctx.facts.update({
            "dex_files": dex,
            "native_libraries": native,
            "manifest_entries": manifests,
            "resource_entry_count": len(resources),
            "detected_engines": engines,
        })
        ctx.add(Evidence(
            id="ev:android-structure",
            kind="structure",
            summary="Mapped Android package structure",
            source=self.name,
            data={
                "dex_count": len(dex),
                "native_count": len(native),
                "manifest_count": len(manifests),
                "resource_entries": len(resources),
                "engines": engines,
            },
        ))


@dataclass(slots=True)
class ToolReadinessStep:
    name: str = "tool-readiness"

    def run(self, ctx: AnalysisContext) -> None:
        import shutil
        tools = {name: bool(shutil.which(name)) for name in ("jadx", "jadx-gui", "ghidraRun", "analyzeHeadless")}
        ctx.facts["tools"] = tools
        ctx.add(Evidence(
            id="ev:tool-readiness",
            kind="environment",
            summary="Checked optional analysis adapters",
            source=self.name,
            data=tools,
        ))


class Pipeline:
    def __init__(self, steps: list[Step] | None = None) -> None:
        self.steps = steps or [FingerprintStep(), AndroidArchiveStep(), ToolReadinessStep()]

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
        out.write_text(json.dumps(ctx.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        return out
