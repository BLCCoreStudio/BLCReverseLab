from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path

from .adapters import GhidraAdapter
from .models import AnalysisContext, Evidence


def _native_priority(name: str) -> tuple[int, str]:
    lower = name.lower()
    important = (
        "libil2cpp.so",
        "libue4.so",
        "libunreal.so",
        "libgame.so",
        "libmain.so",
        "libnative.so",
        "libunity.so",
    )
    return (0 if any(token in lower for token in important) else 1, lower)


@dataclass(slots=True)
class GhidraStep:
    output_root: Path
    timeout_seconds: int = 300
    max_native_targets: int = 8
    name: str = "ghidra"

    def _native_targets(self, ctx: AnalysisContext) -> list[tuple[str, Path]]:
        if ctx.file_type in {"so", "exe", "dll"}:
            return [(ctx.target.name, ctx.target)]
        if ctx.file_type not in {"apk", "aab", "apks", "xapk"} or not zipfile.is_zipfile(ctx.target):
            return []

        members = sorted(
            (str(item) for item in (ctx.facts.get("native_libraries") or [])),
            key=_native_priority,
        )[: max(0, self.max_native_targets)]
        if not members:
            return []

        extraction_root = self.output_root / "ghidra-inputs" / ctx.sha256[:16]
        extraction_root.mkdir(parents=True, exist_ok=True)
        targets: list[tuple[str, Path]] = []
        with zipfile.ZipFile(ctx.target) as zf:
            for index, member in enumerate(members):
                safe_member = member.replace("/", "__")
                destination = extraction_root / f"{index:02d}-{safe_member}"
                try:
                    payload = zf.read(member)
                except KeyError:
                    continue
                destination.write_bytes(payload)
                targets.append((member, destination))
        return targets

    def run(self, ctx: AnalysisContext) -> None:
        adapter = GhidraAdapter(timeout_seconds=self.timeout_seconds, function_sample_limit=80)
        targets = self._native_targets(ctx)
        if not targets:
            ctx.facts["ghidra"] = {
                "available": bool(adapter.resolve()),
                "status": "no-native-targets",
                "analyzed_target_count": 0,
                "results": [],
            }
            ctx.add(
                Evidence(
                    id="ev:ghidra",
                    kind="adapter-result",
                    summary="Ghidra adapter status: no-native-targets",
                    source=self.name,
                    related=["ev:fingerprint"],
                    data=ctx.facts["ghidra"],
                )
            )
            return

        if not adapter.resolve():
            ctx.facts["ghidra"] = {
                "available": False,
                "status": "unavailable",
                "analyzed_target_count": 0,
                "requested_target_count": len(targets),
                "results": [],
            }
            ctx.add(
                Evidence(
                    id="ev:ghidra",
                    kind="adapter-result",
                    summary="Ghidra adapter status: unavailable",
                    source=self.name,
                    related=["ev:fingerprint"],
                    data=ctx.facts["ghidra"],
                )
            )
            return

        results: list[dict[str, object]] = []
        for index, (member, path) in enumerate(targets):
            result = adapter.analyze(
                path,
                self.output_root / "ghidra" / ctx.sha256[:16] / f"target-{index:02d}",
            )
            payload: dict[str, object] = result.to_dict()
            payload["archive_member"] = member if path != ctx.target else None
            results.append(payload)
            relation = f"ev:entry:{member}" if path != ctx.target else "ev:fingerprint"
            ctx.add(
                Evidence(
                    id=f"ev:ghidra-target:{index}",
                    kind="native-function-inventory",
                    summary=f"Ghidra analyzed native target {member}",
                    source=self.name,
                    related=[relation],
                    confidence=0.95 if result.status == "completed" else 0.7,
                    data={
                        "archive_member": payload["archive_member"],
                        "status": result.status,
                        "function_count": result.function_count,
                        "generic_function_count": result.generic_function_count,
                        "external_function_count": result.external_function_count,
                        "thunk_count": result.thunk_count,
                        "jni_candidate_count": result.jni_candidate_count,
                        "jni_candidates": result.jni_candidates,
                        "inventory_path": result.inventory_path,
                    },
                )
            )

        total_functions = sum(int(item.get("function_count", 0)) for item in results)
        generic_functions = sum(int(item.get("generic_function_count", 0)) for item in results)
        jni_candidates = sorted(
            {
                str(name)
                for item in results
                for name in (item.get("jni_candidates") or [])
            }
        )
        completed_count = sum(1 for item in results if item.get("status") == "completed")
        status = "completed" if completed_count == len(results) else "partial"
        generic_ratio = round(generic_functions / total_functions, 4) if total_functions else 0.0
        ctx.facts["ghidra"] = {
            "available": True,
            "status": status,
            "requested_target_count": len(targets),
            "analyzed_target_count": len(results),
            "completed_target_count": completed_count,
            "function_count": total_functions,
            "generic_function_count": generic_functions,
            "generic_function_ratio": generic_ratio,
            "jni_candidate_count": len(jni_candidates),
            "jni_candidates": jni_candidates[:100],
            "results": results,
        }
        ctx.add(
            Evidence(
                id="ev:ghidra",
                kind="adapter-result",
                summary=f"Ghidra native analysis status: {status}",
                source=self.name,
                related=[f"ev:ghidra-target:{index}" for index in range(len(results))],
                confidence=0.95 if status == "completed" else 0.8,
                data={
                    "status": status,
                    "analyzed_target_count": len(results),
                    "function_count": total_functions,
                    "generic_function_count": generic_functions,
                    "generic_function_ratio": generic_ratio,
                    "jni_candidate_count": len(jni_candidates),
                },
            )
        )
