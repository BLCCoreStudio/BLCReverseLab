import zipfile
from pathlib import Path

from blc_reverselab.pipeline import Pipeline


def test_apk_structure_detection(tmp_path: Path):
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"manifest")
        zf.writestr("classes.dex", b"dex")
        zf.writestr("lib/arm64-v8a/libil2cpp.so", b"so")
        zf.writestr("lib/arm64-v8a/libunity.so", b"so")
        zf.writestr("res/layout/main.xml", b"xml")
    ctx = Pipeline().analyze(apk)
    assert ctx.file_type == "apk"
    assert ctx.facts["detected_engines"] == ["unity-il2cpp"]
    assert len(ctx.facts["native_libraries"]) == 2
    assert ctx.completed_steps == ["fingerprint", "android-archive", "tool-readiness"]
