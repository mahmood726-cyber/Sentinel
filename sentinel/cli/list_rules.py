"""`sentinel list-rules` subcommand."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

from sentinel.registry.registry import Registry

RULES_ROOT = Path(__file__).parent.parent / "rules"


def add_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("list-rules", help="List all registered rules")
    p.add_argument("--json", action="store_true", help="Emit as JSON")
    p.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> int:
    reg = Registry.from_dir(RULES_ROOT)
    rules = reg.all_rules()
    if args.json:
        payload = [
            {
                "id": r.id,
                "severity": r.severity.label,
                "scope": r.scope,
                "source": r.source,
            }
            for r in rules
        ]
        print(json.dumps(payload, indent=2))
    else:
        for rule in rules:
            print(f"{rule.id}  [{rule.severity.label}]  scope={rule.scope}  {rule.source}")
    return 0
