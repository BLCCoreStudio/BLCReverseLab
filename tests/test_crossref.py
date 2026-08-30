from pathlib import Path

from blc_reverselab.crossref import JniCrossReferenceAnalyzer


def test_static_jni_cross_reference(tmp_path: Path):
    src = tmp_path / "sources" / "com" / "example"
    src.mkdir(parents=True)
    (src / "Player.java").write_text(
        """
        package com.example;
        public class Player {
            public static native int nativeUpdate(int value);
        }
        """,
        encoding="utf-8",
    )
    report = JniCrossReferenceAnalyzer().analyze(
        tmp_path,
        {"jni_candidates": ["Java_com_example_Player_nativeUpdate", "JNI_OnLoad"]},
    )
    assert report.declaration_count == 1
    assert report.matched_declaration_count == 1
    assert report.dynamic_registration_signal is True
    assert report.declarations[0].matches == ["Java_com_example_Player_nativeUpdate"]
