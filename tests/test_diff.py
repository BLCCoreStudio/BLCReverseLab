from blc_reverselab.diff import compare


def test_diff():
    before = {"facts": {"native_libraries": ["a.so"], "dex_files": ["classes.dex"], "detected_engines": []}}
    after = {"facts": {"native_libraries": ["a.so", "b.so"], "dex_files": ["classes.dex", "classes2.dex"], "detected_engines": ["unity"]}}
    out = compare(before, after)
    assert out.added_native == ["b.so"]
    assert out.added_dex == ["classes2.dex"]
