import pytest

from blc_reverselab.plugins import PluginError, execute_plugin


class DemoPlugin:
    name = "demo"
    version = "1.2.3"

    def analyze(self, report, config):
        return {
            "fact_count": len(report.get("facts", {})),
            "mode": config.get("mode", "default"),
        }


class BadPlugin:
    name = "bad"
    version = "0"

    def analyze(self, report, config):
        return ["not", "a", "dict"]


def test_execute_plugin_wraps_namespaced_result():
    result = execute_plugin(DemoPlugin(), {"facts": {"a": 1}}, {"mode": "safe"})
    assert result["schema_version"] == "blc.reverselab.plugin-result/v1"
    assert result["plugin"]["name"] == "demo"
    assert result["result"]["mode"] == "safe"
    assert result["result"]["fact_count"] == 1


def test_execute_plugin_rejects_invalid_result_contract():
    with pytest.raises(PluginError):
        execute_plugin(BadPlugin(), {"facts": {}}, {})
