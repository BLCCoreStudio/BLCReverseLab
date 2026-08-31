from blc_reverselab.runtime import enrich_with_runtime_observations


def test_runtime_observation_import_rebuilds_evidence_graph():
    report = {"facts": {}, "evidence": [{"id": "ev:fingerprint", "kind": "artifact", "source": "fingerprint", "related": []}], "completed_steps": ["fingerprint"]}
    enriched = enrich_with_runtime_observations(report, {
        "jni_registrations": [{"class": "Game", "method": "tick"}], "observed_calls": ["Game.tick"],
        "plaintext_observations": [], "loaded_modules": ["libgame.so"],
    })
    assert enriched["facts"]["runtime_observations"]["counts"]["observed_calls"] == 1
    assert "runtime-observation-import" in enriched["completed_steps"]
    assert enriched["evidence_graph"]["stats"]["node_count"] == 4
