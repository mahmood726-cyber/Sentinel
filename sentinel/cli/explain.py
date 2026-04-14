"""`sentinel explain <rule-id>` subcommand."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

from sentinel.registry.registry import Registry

RULES_ROOT = Path(__file__).parent.parent / "rules"


def add_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("explain", help="Explain a rule by id")
    p.add_argument("rule_id", help="The rule id to explain")
    p.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> int:
    reg = Registry.from_dir(RULES_ROOT)
    try:
        rule = reg.get(args.rule_id)
    except KeyError as e:
        print(f"error: {e}", file=sys.stderr)
        known = ", ".join(r.id for r in reg.all_rules())
        print(f"known rules: {known}", file=sys.stderr)
        return 1

    print(f"Rule:     {rule.id}")
    print(f"Severity: {rule.severity.label}")
    print(f"Scope:    {rule.scope}")
    print(f"Source:   {rule.source}")
    description = getattr(rule, "description", "")
    if description:
        print(f"\nDescription:\n  {description}")
    fix_hint = getattr(rule, "fix_hint", "")
    if fix_hint:
        print(f"\nFix hint:\n  {fix_hint}")
    return 0
