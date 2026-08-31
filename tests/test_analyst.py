from blc_reverselab.analyst import ask_report


def _report():
    return {
        "facts": {
            "managed_index": {
                "classes": [{"name": "com.blc.InventoryManager"}],
                "methods": [
                    {
                        "class_name": "com.blc.InventoryManager",
                        "name": "loadInventory",
                        "return_type": "void",
                        "parameters": "",
                    }
                ],
                "endpoints": ["https://example.invalid/api/inventory"],
            },
            "ghidra": {"results": []},
            "jni_crossrefs": {"declarations": []},
            "recovery": {"recovered_literals": []},
        },
        "evidence": [
            {
                "id": "managed.inventory",
                "kind": "managed-index",
                "source": "jadx",
                "summary": "InventoryManager loadInventory",
                "confidence": 0.95,
                "data": {},
            }
        ],
    }


def test_analyst_returns_grounded_support():
    result = ask_report(_report(), "inventory load")
    assert result["status"] == "grounded"
    assert result["confidence"] > 0
    assert result["support"]
    assert "managed" in result["layers"]
    assert "Strongest match" in result["answer"]


def test_analyst_refuses_to_invent_missing_answer():
    result = ask_report(_report(), "totally-absent-secret-key")
    assert result["status"] == "insufficient-evidence"
    assert result["confidence"] == 0.0
    assert result["support"] == []
