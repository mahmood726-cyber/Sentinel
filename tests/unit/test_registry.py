import textwrap
from pathlib import Path
import pytest

from sentinel.core import Severity
from sentinel.registry.registry import Registry, EmptyRegistryError


YAML_RULE = """
id: Y-one
severity: WARN
scope: repo
description: y
pattern: 'foo'
source: test.md
"""

PLUGIN_RULE = textwrap.dedent("""
    from sentinel.core import Severity
    ID = 'P-one'
    SEVERITY = Severity.INFO
    SOURCE = 'test.md'
    SCOPE = 'repo'
    def check(ctx):
        return []
""")


def _setup_rules(tmp_path: Path) -> Path:
    root = tmp_path / "rules"
    (root / "yaml").mkdir(parents=True)
    (root / "plugins").mkdir(parents=True)
    (root / "yaml" / "y.yaml").write_text(YAML_RULE, encoding="utf-8")
    (root / "plugins" / "p.py").write_text(PLUGIN_RULE, encoding="utf-8")
    return root


def test_registry_discovers_both_rule_types(tmp_path: Path):
    root = _setup_rules(tmp_path)
    reg = Registry.from_dir(root)
    ids = {r.id for r in reg.all_rules()}
    assert ids == {"Y-one", "P-one"}


def test_registry_get_by_id(tmp_path: Path):
    root = _setup_rules(tmp_path)
    reg = Registry.from_dir(root)
    rule = reg.get("Y-one")
    assert rule.severity == Severity.WARN


def test_registry_get_unknown_raises(tmp_path: Path):
    root = _setup_rules(tmp_path)
    reg = Registry.from_dir(root)
    with pytest.raises(KeyError, match="unknown rule id"):
        reg.get("does-not-exist")


def test_registry_empty_raises(tmp_path: Path):
    root = tmp_path / "rules"
    (root / "yaml").mkdir(parents=True)
    (root / "plugins").mkdir(parents=True)
    with pytest.raises(EmptyRegistryError):
        Registry.from_dir(root)


def test_registry_duplicate_ids_raises(tmp_path: Path):
    root = tmp_path / "rules"
    (root / "yaml").mkdir(parents=True)
    (root / "plugins").mkdir(parents=True)
    dup = YAML_RULE.replace("id: Y-one", "id: DUP")
    (root / "yaml" / "a.yaml").write_text(dup, encoding="utf-8")
    (root / "yaml" / "b.yaml").write_text(dup, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate rule id: DUP"):
        Registry.from_dir(root)
