from __future__ import annotations

from pathlib import Path

from .crossref import JniCrossReferenceStep
from .hotspots import HotspotStep
from .native import GhidraStep
from .pipeline import Pipeline
from .protection import ProtectionStep


def build_pipeline(
    *,
    enable_jadx: bool = False,
    enable_recovery: bool = False,
    enable_ghidra: bool = False,
    deep: bool = False,
    mappings_path: str | Path | None = None,
    workdir: str | Path = ".blc-reverselab",
    ghidra_timeout: int = 300,
    ghidra_max_native: int = 8,
) -> Pipeline:
    if deep:
        enable_recovery = True
        enable_jadx = True
        enable_ghidra = True
    root = Path(workdir)
    pipeline = Pipeline(enable_jadx=enable_jadx or enable_recovery, enable_recovery=enable_recovery,
                        mappings_path=mappings_path, workdir=root)
    if enable_jadx or enable_recovery:
        pipeline.steps.append(HotspotStep())
    if enable_ghidra:
        pipeline.steps.append(GhidraStep(root, timeout_seconds=max(30, ghidra_timeout), max_native_targets=max(1, ghidra_max_native)))
    pipeline.steps.append(ProtectionStep())
    if enable_jadx or enable_recovery or enable_ghidra:
        pipeline.steps.append(JniCrossReferenceStep())
    return pipeline
