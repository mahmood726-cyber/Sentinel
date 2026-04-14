"""Registry: discovers + loads + indexes all rules from a rules/ dir."""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from sentinel.core import Rule
from sentinel.registry.plugin_loader import load_plugin_rule
from sentinel.registry.yaml_loader import load_yaml_rule


class EmptyRegistryError(Exception):
    """Raised when a rules directory contains zero rules (fail-closed)."""


@dataclass
class Registry:
    rules: Dict[str, Rule] = field(default_factory=dict)

    @classmethod
    def from_dir(cls, rules_root: Path) -> "Registry":
        reg = cls()
        yaml_dir = rules_root / "yaml"
        plugins_dir = rules_root / "plugins"

        if yaml_dir.is_dir():
            for yaml_file in sorted(yaml_dir.glob("*.yaml")):
                rule = load_yaml_rule(yaml_file)
                reg._add(rule)

        if plugins_dir.is_dir():
            for py_file in sorted(plugins_dir.glob("*.py")):
                if py_file.name == "__init__.py":
                    continue
                rule = load_plugin_rule(py_file)
                reg._add(rule)

        if not reg.rules:
            raise EmptyRegistryError(
                f"no rules loaded from {rules_root}; empty registry is a "
                f"misconfigured Sentinel (fail-closed)"
            )
        return reg

    def _add(self, rule: Rule) -> None:
        if rule.id in self.rules:
            raise ValueError(f"duplicate rule id: {rule.id}")
        self.rules[rule.id] = rule

    def all_rules(self) -> List[Rule]:
        return list(self.rules.values())

    def get(self, rule_id: str) -> Rule:
        if rule_id not in self.rules:
            raise KeyError(f"unknown rule id: {rule_id}")
        return self.rules[rule_id]
