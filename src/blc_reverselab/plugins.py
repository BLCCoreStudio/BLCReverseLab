from __future__ import annotations

from dataclasses import asdict, dataclass
from importlib.metadata import EntryPoint, entry_points
from typing import Any, Protocol, runtime_checkable

PLUGIN_GROUP = "blc_reverselab.plugins"
PLUGIN_API_VERSION = "1"


class PluginError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class PluginDescriptor:
    name: str
    value: str
    group: str = PLUGIN_GROUP

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@runtime_checkable
class ReverseLabPlugin(Protocol):
    name: str
    version: str

    def analyze(self, report: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]: ...


def _selected_entry_points() -> list[EntryPoint]:
    points = entry_points()
    selected = points.select(group=PLUGIN_GROUP)
    return sorted(selected, key=lambda item: item.name)


def discover_plugins() -> list[PluginDescriptor]:
    """Discover plugin metadata without importing or executing plugin code."""
    return [PluginDescriptor(name=item.name, value=item.value, group=item.group) for item in _selected_entry_points()]


def execute_plugin(plugin: Any, report: dict[str, Any], config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute an explicitly supplied plugin behind a small validated contract."""
    config = dict(config or {})
    analyze = getattr(plugin, "analyze", None)
    if not callable(analyze):
        raise PluginError("plugin must provide analyze(report, config)")

    result = analyze(report, config)
    if not isinstance(result, dict):
        raise PluginError("plugin analyze() must return a dict")

    name = str(getattr(plugin, "name", plugin.__class__.__name__))
    version = str(getattr(plugin, "version", "unknown"))
    return {
        "schema_version": "blc.reverselab.plugin-result/v1",
        "plugin_api_version": PLUGIN_API_VERSION,
        "plugin": {"name": name, "version": version},
        "result": result,
    }


def run_installed_plugin(
    name: str,
    report: dict[str, Any],
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Load and run one plugin only after the caller explicitly names it."""
    matches = [item for item in _selected_entry_points() if item.name == name]
    if not matches:
        available = ", ".join(item.name for item in _selected_entry_points()) or "none"
        raise PluginError(f"plugin {name!r} is not installed; available: {available}")
    if len(matches) > 1:
        raise PluginError(f"multiple installed plugins use the name {name!r}")

    loaded = matches[0].load()
    plugin = loaded() if isinstance(loaded, type) else loaded
    return execute_plugin(plugin, report, config)
