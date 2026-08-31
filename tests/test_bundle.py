import json
import zipfile

from blc_reverselab.bundle import create_bundle
from blc_reverselab.report import render_analysis_html


def test_bundle_contains_machine_and_human_reports(tmp_path):
    report = {"sha256": "abc", "file_type": "apk", "facts": {}, "evidence": [], "completed_steps": []}
    output = create_bundle(report, tmp_path / "sample.blc.zip", version_diff={"change_count": 1})
    with zipfile.ZipFile(output) as zf:
        assert set(zf.namelist()) == {"manifest.json", "analysis.json", "report.html", "version-diff.json"}
        manifest = json.loads(zf.read("manifest.json"))
        assert manifest["artifact_sha256"] == "abc"


def test_interactive_report_contains_evidence_explorer():
    html = render_analysis_html({"file_type": "apk", "facts": {}, "evidence": [{"id": "ev:1", "kind": "artifact", "source": "test", "summary": "hello"}]})
    assert "Evidence Explorer" in html
    assert "ev:1" in html
    assert "data-search" in html
