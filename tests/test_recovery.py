from pathlib import Path

from blc_reverselab.recovery import RecoveryAnalyzer


def test_recovery_profiles_obfuscation_and_reversible_literals(tmp_path: Path):
    sources = tmp_path / "sources" / "a"
    sources.mkdir(parents=True)
    (sources / "b.java").write_text(
        """
        package a;
        class b {
            String one = "SGVsbG8gV29ybGQh";
            String two = "48656c6c6f21";
            String noisy = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";
        }
        """,
        encoding="utf-8",
    )

    report = RecoveryAnalyzer().analyze(tmp_path)
    assert report.status == "completed"
    assert report.java_file_count == 1
    assert report.suspicious_identifier_count >= 2
    assert report.obfuscation_score > 0
    assert report.recovered_literal_count == 2
    assert {item.encoding for item in report.recovered_literals} == {"base64", "hex"}
    assert report.capabilities["original_source_guarantee"] is False


def test_recovery_without_decompiler_output_is_nonfatal(tmp_path: Path):
    report = RecoveryAnalyzer().analyze(tmp_path / "missing")
    assert report.status == "no-decompiler-output"
    assert report.recovered_literal_count == 0
