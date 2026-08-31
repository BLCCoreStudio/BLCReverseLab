from __future__ import annotations

import shutil
import subprocess
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(slots=True)
class ToolStatus:
    name: str
    available: bool
    path: str | None
    version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _version(command: list[str]) -> str | None:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (completed.stdout or completed.stderr or "").strip().splitlines()
    return text[0][:200] if text else None


def doctor() -> dict[str, Any]:
    specs = {
        "jadx": ["jadx", "--version"],
        "ghidra-headless": ["analyzeHeadless", "-version"],
        "java": ["java", "-version"],
    }
    tools: list[ToolStatus] = []
    for name, command in specs.items():
        path = shutil.which(command[0])
        version = _version([path, *command[1:]]) if path else None
        tools.append(ToolStatus(name=name, available=bool(path), path=path, version=version))
    return {
        "schema_version": "blc.reverselab.doctor/v1",
        "ready_for_managed": any(item.name == "jadx" and item.available for item in tools),
        "ready_for_native": any(item.name == "ghidra-headless" and item.available for item in tools),
        "tools": [item.to_dict() for item in tools],
    }
