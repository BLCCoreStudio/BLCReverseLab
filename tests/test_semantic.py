from blc_reverselab.semantic import match_native_functions


def _report(items):
    return {
        "facts": {
            "ghidra": {
                "results": [
                    {
                        "archive_member": "lib/arm64-v8a/libgame.so",
                        "function_fingerprints": items,
                    }
                ]
            }
        }
    }


def test_native_semantic_matching_name_and_shape():
    before = _report(
        [
            {"name": "KnownFunction", "address": "0010", "shape_id": "aaaa", "generic_name": False, "external": False},
            {"name": "FUN_0020", "address": "0020", "shape_id": "bbbb", "generic_name": True, "external": False},
        ]
    )
    after = _report(
        [
            {"name": "KnownFunction", "address": "1010", "shape_id": "cccc", "generic_name": False, "external": False},
            {"name": "FUN_2020", "address": "2020", "shape_id": "bbbb", "generic_name": True, "external": False},
        ]
    )
    result = match_native_functions(before, after)
    assert result["native_semantic_match_count"] == 2
    assert result["native_function_reuse_ratio"] == 1.0
    assert {item["method"] for item in result["native_semantic_matches"]} == {"stable-name", "unique-shape"}
