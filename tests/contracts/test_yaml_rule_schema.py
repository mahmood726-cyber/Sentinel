"""Contract: every shipped YAML rule parses with all required fields."""
from pathlib import Path
import pytest
from sentinel.registry.yaml_loader import load_yaml_rule

YAML_DIR = Path(__file__).parent.parent.parent / "sentinel" / "rules" / "yaml"


@pytest.mark.contract
@pytest.mark.parametrize("yaml_file", sorted(YAML_DIR.glob("*.yaml")), ids=lambda p: p.name)
def test_shipped_yaml_rules_load(yaml_file: Path):
    rule = load_yaml_rule(yaml_file)
    assert rule.id
    assert rule.severity
    assert rule.source
    assert rule.scope in ("repo", "portfolio")
