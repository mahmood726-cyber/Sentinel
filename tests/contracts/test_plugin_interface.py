"""Contract: every shipped plugin exposes the required interface."""
from pathlib import Path
import pytest
from sentinel.registry.plugin_loader import load_plugin_rule

PLUGINS_DIR = Path(__file__).parent.parent.parent / "sentinel" / "rules" / "plugins"


def _plugin_files():
    return sorted(p for p in PLUGINS_DIR.glob("*.py") if p.name != "__init__.py")


@pytest.mark.contract
@pytest.mark.parametrize("plugin_file", _plugin_files(), ids=lambda p: p.name)
def test_shipped_plugins_load(plugin_file: Path):
    rule = load_plugin_rule(plugin_file)
    assert rule.id
    assert rule.severity
    assert rule.source
    assert rule.scope in ("repo", "portfolio")
    assert callable(rule._check)
