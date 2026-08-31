import json
from pathlib import Path

from blc_reverselab.workspace import add_analysis, init_workspace, read_workspace


def test_workspace_tracks_analysis_by_sha(tmp_path: Path):
    init_workspace(tmp_path, "demo")
    analysis = tmp_path / "analysis.json"
    analysis.write_text(json.dumps({"sha256": "abc", "target": "/tmp/app.apk", "file_type": "apk"}), encoding="utf-8")
    add_analysis(tmp_path, analysis)
    workspace = read_workspace(tmp_path)
    assert workspace["name"] == "demo"
    assert workspace["analyses"][0]["sha256"] == "abc"
