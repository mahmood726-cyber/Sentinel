"""`sentinel list-rules` subcommand."""
from __future__ import annotations
import argparse
from pathlib import Path

from sentinel.registry.registry import Registry

RULES_ROOT = Path(__file__).parent.parent / "rules"


def add_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("list-rules", help="List all registered rules")
    p.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> int:
    reg = Registry.from_dir(RULES_ROOT)
    for rule in reg.all_rules():
        print(f"{rule.id}  [{rule.severity.label}]  scope={rule.scope}  {rule.source}")
    return 0
