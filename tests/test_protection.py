import zipfile
from pathlib import Path

from blc_reverselab.protection import ProtectionAnalyzer


def test_protection_fingerprint_and_obfuscation_signal(tmp_path: Path):
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("classes.dex", b"dex")
        zf.writestr("lib/arm64-v8a/libjiagu.so", b"native")

    report = ProtectionAnalyzer().analyze(
        apk,
        {
            "recovery": {
                "obfuscation_score": 0.8,
                "high_entropy_literal_count": 3,
                "recovered_literal_count": 1,
            },
            "ghidra": {"function_count": 100, "generic_function_ratio": 0.75},
        },
    )
    assert report.level in {"medium", "high"}
    names = {signal.name for signal in report.signals}
    assert "jiagu-like" in names
    assert "high-obfuscation" in names
    assert "heavily-stripped-native-surface" in names
