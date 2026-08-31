from blc_reverselab.profiles import build_pipeline


def test_deep_profile_contains_advanced_steps():
    pipeline = build_pipeline(deep=True, workdir=".tmp")
    names = [step.name for step in pipeline.steps]
    assert "jadx" in names
    assert "recovery" in names
    assert "decompiler-hotspots" in names
    assert "ghidra" in names
    assert "protection-profile" in names
    assert "jni-crossrefs" in names
