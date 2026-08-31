from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .report import render_analysis_html


def create_bundle(
    report: dict[str, Any],
    output: str | Path,
    *,
    version_diff: dict[str, Any] | None = None,
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": "blc.reverselab.bundle/v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "artifact_sha256": report.get("sha256"),
        "artifact_type": report.get("file_type"),
        "contains": ["analysis.json", "report.html"] + (["version-diff.json"] if version_diff else []),
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        zf.writestr("analysis.json", json.dumps(report, indent=2, sort_keys=True) + "\n")
        zf.writestr("report.html", render_analysis_html(report))
        if version_diff is not None:
            zf.writestr("version-diff.json", json.dumps(version_diff, indent=2, sort_keys=True) + "\n")
    return path
