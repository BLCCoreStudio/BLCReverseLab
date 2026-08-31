from pathlib import Path

from blc_reverselab.managed import ManagedIndexer
from blc_reverselab.query import search_report


def test_managed_index_extracts_classes_methods_and_endpoints(tmp_path: Path):
    src = tmp_path / "sources" / "com" / "example"; src.mkdir(parents=True)
    (src / "Api.java").write_text('''package com.example;
public class Api {
  public native int tick(int value);
  public String login() { return "https://api.example.com/v1/login"; }
}''', encoding="utf-8")
    report = ManagedIndexer().analyze(tmp_path)
    assert report.class_count == 1
    assert report.method_count >= 2
    assert report.native_method_count >= 1
    assert "https://api.example.com/v1/login" in report.endpoints


def test_universal_search_hits_managed_native_and_evidence():
    report = {"facts": {"managed_index": {"classes": [{"name": "com.example.Inventory"}], "methods": [{"class_name": "com.example.Inventory", "name": "loadItems", "return_type": "void", "parameters": ""}], "endpoints": ["/api/inventory"]}, "ghidra": {"results": [{"archive_member": "libgame.so", "function_fingerprints": [{"name": "InventoryNative", "address": "1000", "shape_id": "abc"}]}]}}, "evidence": [{"id": "ev:inventory", "kind": "test", "source": "unit", "summary": "inventory evidence"}]}
    result = search_report(report, "inventory")
    kinds = {item["kind"] for item in result["results"]}
    assert {"managed-class", "managed-method", "endpoint", "native-function", "evidence"}.issubset(kinds)
