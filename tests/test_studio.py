import json
import threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen

from blc_reverselab.studio import create_studio_server, render_studio_app
from blc_reverselab.workspace import add_analysis, init_workspace


def _report(path: Path, sha: str, target: str, *, newer: bool = False) -> Path:
    classes = [{"name": "com.example.InventoryManager"}]
    methods = [{"class_name": "com.example.InventoryManager", "name": "nativeSync", "parameters": ""}]
    endpoints = ["https://api.example.test/inventory"]
    if newer:
        classes.append({"name": "com.example.StoreManager"})
        methods.append({"class_name": "com.example.StoreManager", "name": "refresh", "parameters": ""})
        endpoints.append("https://api.example.test/store")

    payload = {
        "schema_version": "blc.reverselab.analysis/v1",
        "target": target,
        "sha256": sha,
        "file_type": "apk",
        "completed_steps": ["managed-index", "jni-crossref"],
        "facts": {
            "native_libraries": ["lib/arm64-v8a/libgame.so"],
            "dex_files": ["classes.dex"],
            "tracked_entries": {
                "classes.dex": {"kind": "dex", "crc32": "2222" if newer else "1111", "size": 20},
                "lib/arm64-v8a/libgame.so": {"kind": "native", "crc32": "3333", "size": 40},
            },
            "managed_index": {"classes": classes, "methods": methods, "endpoints": endpoints},
            "ghidra": {
                "function_count": 1,
                "results": [{
                    "archive_member": "lib/arm64-v8a/libgame.so",
                    "function_fingerprints": [{
                        "name": "Java_com_example_InventoryManager_nativeSync",
                        "address": "0x2000" if newer else "0x1000",
                        "shape_id": "inventory-shape",
                        "generic_name": False,
                        "external": False,
                    }],
                }],
            },
            "jni_crossrefs": {
                "matched_declaration_count": 1,
                "unresolved_declaration_count": 0,
                "declarations": [{
                    "class_name": "com.example.InventoryManager",
                    "method_name": "nativeSync",
                    "expected_jni_symbol": "Java_com_example_InventoryManager_nativeSync",
                    "matches": ["Java_com_example_InventoryManager_nativeSync"],
                }],
            },
            "recovery": {
                "obfuscation_score": 0.2 if newer else 0.1,
                "recovered_literal_count": 0,
                "high_entropy_literal_count": 0,
                "recovered_literals": [],
            },
            "protection": {"level": "medium", "score": 0.4, "signals": []},
        },
        "evidence": [{
            "id": "ev:inventory-new" if newer else "ev:inventory",
            "kind": "managed-class",
            "source": "managed-index",
            "summary": "Inventory manager is present",
            "confidence": 0.95,
            "related": [],
            "data": {},
        }],
        "evidence_graph": {"nodes": [], "edges": [], "unresolved_targets": [], "stats": {}},
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_studio_html_contains_premium_surfaces():
    page = render_studio_app("Demo")
    assert "Investigation Studio" in page
    assert "Evidence Analyst" in page
    assert "Cross-layer graph" in page
    assert "Universal search" in page
    assert "Version intelligence" in page
    assert "Compare → current" in page


def test_studio_http_api_is_read_only_grounded_and_version_aware(tmp_path: Path):
    root = tmp_path / "workspace"
    init_workspace(root, "Studio Lab")
    old_sha = "c" * 64
    new_sha = "d" * 64
    add_analysis(root, _report(tmp_path / "old.json", old_sha, "/tmp/sample-old.apk"))
    add_analysis(root, _report(tmp_path / "new.json", new_sha, "/tmp/sample-new.apk", newer=True))

    server = create_studio_server(root, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with urlopen(base + "/api/health", timeout=3) as response:
            health = json.loads(response.read().decode())
            assert health == {"mode": "read-only", "status": "ok", "surface": "studio"}
            assert response.headers["X-Frame-Options"] == "DENY"

        with urlopen(base + f"/api/graph?sha={new_sha}", timeout=3) as response:
            graph = json.loads(response.read().decode())
            assert graph["stats"]["node_count"] >= 4
            assert any(edge["relation"] == "resolves-to" for edge in graph["edges"])

        with urlopen(base + f"/api/ask?sha={new_sha}&q=inventory", timeout=3) as response:
            answer = json.loads(response.read().decode())
            assert answer["status"] == "grounded"
            assert answer["support"]

        with urlopen(base + f"/api/search?sha={new_sha}&q=inventory", timeout=3) as response:
            results = json.loads(response.read().decode())
            assert results["result_count"] >= 1

        with urlopen(base + f"/api/version?before={old_sha}&after={new_sha}", timeout=3) as response:
            version = json.loads(response.read().decode())
            assert version["schema_version"] == "blc.reverselab.version-intelligence/v1"
            assert version["managed"]["classes"]["added"] == ["com.example.StoreManager"]
            assert "managed" in version["changed_surfaces"]
            assert version["focus"]

        try:
            urlopen(base + "/api/ask?sha=missing&q=test", timeout=3)
            assert False, "unknown workspace analysis must fail"
        except HTTPError as exc:
            assert exc.code == 404

        try:
            urlopen(base + f"/api/version?before={old_sha}", timeout=3)
            assert False, "incomplete version query must fail"
        except HTTPError as exc:
            assert exc.code == 400
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
