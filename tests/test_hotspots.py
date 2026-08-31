from pathlib import Path

from blc_reverselab.hotspots import DecompilerHotspotAnalyzer


def test_decompiler_hotspot_detects_failure(tmp_path: Path):
    source = tmp_path / "sources"; source.mkdir()
    (source / "Broken.java").write_text("class Broken {\n/* JADX WARN: bad */\n// Method not decompiled\n" + "if (x) {}\n" * 100 + "}", encoding="utf-8")
    report = DecompilerHotspotAnalyzer().analyze(tmp_path)
    assert report.decompiler_warning_count >= 1
    assert report.not_decompiled_count == 1
    assert report.hotspot_count == 1
    assert report.hotspots[0].score == 1.0
