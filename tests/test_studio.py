import json
import threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen

from blc_reverselab.studio import create_studio_server, render_studio_app
from blc_reverselab.workspace import add_analysis, init_workspace


def _report(path: Path) -> Path:
    payload = {
        "schema_version": "blc.reverselab.analysis/v1",
        "target": "/tmp/sample.apk",
        "sha256": "d" * 64,
        "file_type": "apk",
        "completed_steps": ["managed-index", "jni-crossref"],
        "facts": {
            "managed_index": {
                "classes": [{"name": "com.example.InventoryManager"}],
                "methods": [{"class_name": "com.example.InventoryManager", "name": "nativeSync"}],
                "endpoints": ["https://api.example.test/inventory"],
            },
            "ghidra": {
                "function_count": 1,
                "results": [{
                    "archive_member": "lib/arm64-v8a/libgame.so",
                    "function_fingerprints": [{"name": "Java_com_example_InventoryManager_nativeSync", "address": "0x1000"}],
                }],
            },
            "jni_crossrefs": {
                "matched_declaration_count": 1,
                "declarations": [{
                    "class_name": "com.example.InventoryManager",
                    "method_name": "nativeSync",
                    "matches": ["Java_com_example_InventoryManager_nativeSync"],
                }],
            },
            "recovery": {"obfuscation_score": 0.1, "recovered_literals": []},
            "protection": {"level": "medium"},
        },
        "evidence": [{
            "id": "ev:inventory",
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


def test_studio_http_api_is_read_only_and_grounded(tmp_path: Path):
    root = tmp_path / "workspace"
    init_workspace(root, "Studio Lab")
    add_analysis(root, _report(tmp_path / "analysis.json"))

    server = create_studio_server(root, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    sha = "d" * 64
    try:
        with urlopen(base + "/api/health", timeout=3) as response:
            health = json.loads(response.read().decode())
            assert health == {"mode": "read-only", "status": "ok", "surface": "studio"}
            assert response.headers["X-Frame-Options"] == "DENY"

        with urlopen(base + f"/api/graph?sha={sha}", timeout=3) as response:
            graph = json.loads(response.read().decode())
            assert graph["stats"]["node_count"] >= 4
            assert any(edge["relation"] == "resolves-to" for edge in graph["edges"])

        with urlopen(base + f"/api/ask?sha={sha}&q=inventory", timeout=3) as response:
            answer = json.loads(response.read().decode())
            assert answer["status"] == "grounded"
            assert answer["support"]

        with urlopen(base + f"/api/search?sha={sha}&q=inventory", timeout=3) as response:
            results = json.loads(response.read().decode())
            assert results["result_count"] >= 1

        try:
            urlopen(base + "/api/ask?sha=missing&q=test", timeout=3)
            assert False, "unknown workspace analysis must fail"
        except HTTPError as exc:
            assert exc.code == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
