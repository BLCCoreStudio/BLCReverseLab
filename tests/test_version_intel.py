from blc_reverselab.version_intel import build_version_intelligence


def _report(*, sha: str, newer: bool):
    classes = [{"name": "com.example.Player"}]
    methods = [{"class_name": "com.example.Player", "name": "nativeTick", "parameters": "int value"}]
    endpoints = ["https://api.example.test/player"]
    if newer:
        classes.append({"name": "com.example.Inventory"})
        methods.append({"class_name": "com.example.Inventory", "name": "refresh", "parameters": ""})
        endpoints.append("https://api.example.test/inventory")

    native_name = "Java_com_example_Player_nativeTick"
    native_items = [
        {
            "name": native_name,
            "address": "0x2000" if newer else "0x1000",
            "shape_id": "shape-player",
            "generic_name": False,
            "external": False,
        }
    ]
    if newer:
        native_items.append(
            {
                "name": "FUN_3000",
                "address": "0x3000",
                "shape_id": "shape-new",
                "generic_name": True,
                "external": False,
            }
        )

    tracked = {
        "classes.dex": {"kind": "dex", "crc32": "2222" if newer else "1111", "size": 20},
        "lib/arm64-v8a/libgame.so": {"kind": "native", "crc32": "4444" if newer else "3333", "size": 40},
    }
    if newer:
        tracked["classes2.dex"] = {"kind": "dex", "crc32": "5555", "size": 10}

    return {
        "schema_version": "blc.reverselab.analysis/v1",
        "target": "/tmp/game-new.apk" if newer else "/tmp/game-old.apk",
        "sha256": sha,
        "file_type": "apk",
        "facts": {
            "native_libraries": ["lib/arm64-v8a/libgame.so"],
            "dex_files": ["classes.dex"] + (["classes2.dex"] if newer else []),
            "tracked_entries": tracked,
            "resource_entry_count": 12 if newer else 10,
            "detected_engines": ["unity-il2cpp"],
            "managed_index": {"classes": classes, "methods": methods, "endpoints": endpoints},
            "ghidra": {
                "function_count": len(native_items),
                "results": [{"archive_member": "lib/arm64-v8a/libgame.so", "function_fingerprints": native_items}],
            },
            "jni_crossrefs": {
                "matched_declaration_count": 1,
                "unresolved_declaration_count": 0,
                "dynamic_registration_signal": newer,
                "declarations": [
                    {
                        "class_name": "com.example.Player",
                        "method_name": "nativeTick",
                        "expected_jni_symbol": native_name,
                        "matches": [native_name],
                    }
                ],
            },
            "recovery": {
                "obfuscation_score": 0.55 if newer else 0.15,
                "recovered_literal_count": 2 if newer else 1,
                "high_entropy_literal_count": 3 if newer else 0,
            },
            "protection": {
                "level": "medium" if newer else "low",
                "score": 0.5 if newer else 0.2,
                "signals": ([{"category": "obfuscation", "name": "moderate-obfuscation"}] if newer else []),
            },
        },
        "evidence": [{"id": "ev:new" if newer else "ev:old"}],
    }


def test_version_intelligence_prioritizes_changed_cross_layer_surfaces():
    before = _report(sha="a" * 64, newer=False)
    after = _report(sha="b" * 64, newer=True)

    result = build_version_intelligence(before, after)

    assert result["schema_version"] == "blc.reverselab.version-intelligence/v1"
    assert "managed" in result["changed_surfaces"]
    assert "native" in result["changed_surfaces"]
    assert "protection" in result["changed_surfaces"]
    assert "recovery" in result["changed_surfaces"]
    assert result["managed"]["classes"]["added"] == ["com.example.Inventory"]
    assert "https://api.example.test/inventory" in result["managed"]["endpoints"]["added"]
    assert result["native"]["semantic_match_count"] == 1
    assert result["native"]["unmatched_after"] == 1
    assert result["protection"]["level_before"] == "low"
    assert result["protection"]["level_after"] == "medium"
    assert result["recovery"]["obfuscation_delta"] == 0.4
    assert result["focus"]
    assert result["impact"] in {"medium", "high"}


def test_version_intelligence_has_no_focus_when_reports_are_identical():
    report = _report(sha="c" * 64, newer=False)
    result = build_version_intelligence(report, report)
    assert result["changed_surfaces"] == []
    assert result["focus"] == []
    assert result["impact"] == "none"
