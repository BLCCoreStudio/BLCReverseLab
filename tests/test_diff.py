from blc_reverselab.diff import compare


def test_diff_detects_added_inventory():
    before = {"facts": {"native_libraries": ["a.so"], "dex_files": ["classes.dex"], "detected_engines": []}}
    after = {
        "facts": {
            "native_libraries": ["a.so", "b.so"],
            "dex_files": ["classes.dex", "classes2.dex"],
            "detected_engines": ["unity"],
        }
    }
    out = compare(before, after)
    assert out.added_native == ["b.so"]
    assert out.added_dex == ["classes2.dex"]


def test_diff_detects_changed_file_with_same_name():
    before = {
        "facts": {
            "native_libraries": ["lib/a.so"],
            "dex_files": ["classes.dex"],
            "detected_engines": ["unity"],
            "resource_entry_count": 5,
            "tracked_entries": {
                "classes.dex": {"kind": "dex", "crc32": "11111111", "size": 10},
                "lib/a.so": {"kind": "native", "crc32": "22222222", "size": 20},
            },
        },
        "evidence": [{"id": "ev:old"}],
    }
    after = {
        "facts": {
            "native_libraries": ["lib/a.so"],
            "dex_files": ["classes.dex"],
            "detected_engines": ["unity"],
            "resource_entry_count": 7,
            "tracked_entries": {
                "classes.dex": {"kind": "dex", "crc32": "33333333", "size": 11},
                "lib/a.so": {"kind": "native", "crc32": "22222222", "size": 20},
            },
        },
        "evidence": [{"id": "ev:new"}],
    }

    out = compare(before, after)
    assert out.changed_dex == ["classes.dex"]
    assert out.changed_native == []
    assert out.resource_entry_delta == 2
    assert out.analysis_reuse_ratio == 0.5
    assert out.evidence_added == ["ev:new"]
    assert out.evidence_removed == ["ev:old"]
