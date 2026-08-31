from blc_reverselab.explorer import build_analysis_graph, graph_to_dot


def test_cross_layer_graph_links_managed_jni_native():
    report = {
        "facts": {
            "managed_index": {
                "classes": [{"name": "com.blc.Sample"}],
                "methods": [{"class_name": "com.blc.Sample", "name": "nativeTick"}],
                "endpoints": ["https://example.invalid/api"],
            },
            "ghidra": {
                "results": [
                    {
                        "target": "libsample.so",
                        "function_fingerprints": [
                            {
                                "name": "Java_com_blc_Sample_nativeTick",
                                "address": "00100000",
                                "shape_id": "shape-1",
                            }
                        ],
                    }
                ]
            },
            "jni_crossrefs": {
                "declarations": [
                    {
                        "class_name": "com.blc.Sample",
                        "method_name": "nativeTick",
                        "matches": ["Java_com_blc_Sample_nativeTick"],
                    }
                ]
            },
            "recovery": {"recovered_literals": []},
        },
        "evidence": [],
        "evidence_graph": {"edges": []},
    }

    graph = build_analysis_graph(report)
    relations = {item["relation"] for item in graph["edges"]}
    assert graph["stats"]["layers"]["managed"] == 2
    assert graph["stats"]["layers"]["jni"] == 1
    assert graph["stats"]["layers"]["native"] == 1
    assert "declares-native" in relations
    assert "resolves-to" in relations

    dot = graph_to_dot(graph)
    assert dot.startswith("digraph BLCReverseLab")
    assert "resolves-to" in dot
