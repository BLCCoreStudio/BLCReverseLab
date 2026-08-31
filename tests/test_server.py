import json
import threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen

from blc_reverselab.server import WorkspaceStore, create_workspace_server, render_workspace_app
from blc_reverselab.workspace import add_analysis, init_workspace


def _analysis(path: Path, sha: str, target: str, *, evidence_summary: str = "Inventory manager") -> Path:
    payload = {
        "schema_version": "blc.reverselab.analysis/v1",
        "target": target,
        "sha256": sha,
        "file_type": "apk",
        "completed_steps": ["fingerprint", "android-archive"],
        "facts": {
            "detected_engines": ["unity-il2cpp"],
            "managed_index": {
                "classes": [{"name": "com.example.InventoryManager"}],
                "methods": [],
                "endpoints": ["https://api.example.test/inventory"],
            },
            "ghidra": {"function_count": 17},
            "recovery": {"obfuscation_score": 0.25},
            "protection": {"level": "medium"},
            "jni_crossrefs": {"matched_declaration_count": 1},
        },
        "evidence": [
            {
                "id": "ev:inventory",
                "kind": "managed-class",
                "source": "managed-index",
                "summary": evidence_summary,
            }
        ],
        "evidence_graph": {"nodes": [], "edges": [], "unresolved_targets": [], "stats": {"node_count": 0, "edge_count": 0}},
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_workspace_store_snapshot_search_and_diff(tmp_path: Path):
    root = tmp_path / "workspace"
    init_workspace(root, "Demo Lab")
    old = _analysis(tmp_path / "old.json", "a" * 64, "/tmp/game-old.apk")
    new = _analysis(tmp_path / "new.json", "b" * 64, "/tmp/game-new.apk", evidence_summary="Inventory manager changed")
    add_analysis(root, old)
    add_analysis(root, new)

    store = WorkspaceStore.open(root)
    snapshot = store.snapshot()
    assert snapshot["name"] == "Demo Lab"
    assert snapshot["analysis_count"] == 2
    assert snapshot["analyses"][0]["summary"]["native_function_count"] == 17

    search = store.search("b" * 64, "inventory")
    assert search["result_count"] >= 1
    assert any(item["kind"] == "managed-class" for item in search["results"])

    diff = store.diff("a" * 64, "b" * 64)
    assert "change_count" in diff


def test_local_workspace_http_api(tmp_path: Path):
    root = tmp_path / "workspace"
    init_workspace(root, "HTTP Lab")
    report = _analysis(tmp_path / "analysis.json", "c" * 64, "/tmp/game.apk")
    add_analysis(root, report)

    server = create_workspace_server(root, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with urlopen(base + "/api/health", timeout=3) as response:
            health = json.loads(response.read().decode("utf-8"))
            assert health["status"] == "ok"
            assert health["mode"] == "read-only"
            assert response.headers["X-Content-Type-Options"] == "nosniff"

        with urlopen(base + "/api/workspace", timeout=3) as response:
            workspace = json.loads(response.read().decode("utf-8"))
            assert workspace["analysis_count"] == 1

        with urlopen(base + "/api/search?sha=" + "c" * 64 + "&q=inventory", timeout=3) as response:
            results = json.loads(response.read().decode("utf-8"))
            assert results["result_count"] >= 1

        with urlopen(base + "/analysis/" + "c" * 64, timeout=3) as response:
            html = response.read().decode("utf-8")
            assert "BLCReverseLab" in html
            assert "Inventory" in html

        try:
            urlopen(base + "/api/analysis/missing", timeout=3)
            assert False, "missing analysis must return an error"
        except HTTPError as exc:
            assert exc.code == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_workspace_app_contains_local_ide_surfaces():
    html = render_workspace_app("Demo")
    assert "Local Workspace IDE" in html
    assert "Universal search" in html
    assert "Version intelligence" in html
    assert "/api/workspace" in html
