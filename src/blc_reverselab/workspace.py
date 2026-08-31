from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

WORKSPACE_FILE = "blc-workspace.json"


def _workspace_path(root: str | Path) -> Path:
    return Path(root).expanduser().resolve() / WORKSPACE_FILE


def init_workspace(root: str | Path, name: str) -> Path:
    directory = Path(root).expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / WORKSPACE_FILE
    if path.exists():
        raise FileExistsError(path)
    payload = {"schema_version": "blc.reverselab.workspace/v1", "name": name,
               "created_at": datetime.now(timezone.utc).isoformat(), "analyses": []}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def add_analysis(root: str | Path, analysis_path: str | Path) -> Path:
    path = _workspace_path(root)
    payload = json.loads(path.read_text(encoding="utf-8"))
    analysis_file = Path(analysis_path).expanduser().resolve()
    report = json.loads(analysis_file.read_text(encoding="utf-8"))
    entry = {"sha256": report.get("sha256"), "target": report.get("target"),
             "file_type": report.get("file_type"), "analysis_path": str(analysis_file),
             "added_at": datetime.now(timezone.utc).isoformat()}
    existing = [item for item in payload.get("analyses", []) if item.get("sha256") != entry["sha256"]]
    existing.append(entry)
    payload["analyses"] = existing
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def read_workspace(root: str | Path) -> dict[str, Any]:
    return json.loads(_workspace_path(root).read_text(encoding="utf-8"))
