"""Check rule-file SHA-256 hashes against rules-manifest.json.

Detects accidental drift, not tampering by someone able to edit the repo.
Use --update after intentional rule changes. No key or signature is needed;
legacy signature fields are ignored. Use --json for machine-readable output.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from typing import Any

from sentinel.registry.rule_integrity import (
    DEFAULT_MANIFEST_REL,
    compare,
    compute_manifest,
    load_manifest_full,
    write_manifest,
)


def _sentinel_repo_root() -> Path:
    # `sentinel/cli/verify_rules.py` -> `<repo>`
    return Path(__file__).parent.parent.parent


def add_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "verify-rules",
        help="Check rule files against rules-manifest.json (or regenerate)",
    )
    p.add_argument(
        "--update", action="store_true",
        help="Write the current rule hashes to rules-manifest.json. "
             "Use after intentionally adding/removing/modifying a rule.",
    )
    p.add_argument(
        "--json", action="store_true",
        help="Emit drift report as JSON to stdout",
    )
    p.add_argument(
        "--manifest", type=Path, default=None,
        help=f"Override manifest path (default: <repo>/{DEFAULT_MANIFEST_REL})",
    )
    p.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> int:
    repo_root = _sentinel_repo_root()
    rules_root = repo_root / "sentinel" / "rules"
    if not rules_root.is_dir():
        print(
            f"[verify-rules] rule dir not found at {rules_root}",
            file=sys.stderr,
        )
        return 2
    manifest_path = args.manifest or (repo_root / DEFAULT_MANIFEST_REL)
    current = compute_manifest(rules_root)

    if args.update:
        return _run_update(args, manifest_path, current)

    return _run_check(args, manifest_path, current)


def _run_update(
    args: argparse.Namespace,
    manifest_path: Path,
    current: dict[str, str],
) -> int:
    write_manifest(manifest_path, current)
    if args.json:
        print(json.dumps({
            "status": "updated",
            "rule_count": len(current),
            "path": str(manifest_path),
        }))
    else:
        print(
            f"[verify-rules] wrote {len(current)} rule hash(es) to "
            f"{manifest_path}",
        )
    return 0


def _run_check(
    args: argparse.Namespace,
    manifest_path: Path,
    current: dict[str, str],
) -> int:
    doc = load_manifest_full(manifest_path)
    if doc is None:
        msg = (
            f"[verify-rules] no manifest at {manifest_path}; "
            "run with --update to create one"
        )
        if args.json:
            print(json.dumps({"status": "no_manifest", "path": str(manifest_path)}))
        else:
            print(msg, file=sys.stderr)
        return 2

    report = compare(current, doc.rules)
    if args.json:
        out: dict[str, Any] = {
            "status": "drift" if report.has_drift else "ok",
            "added": report.added,
            "removed": report.removed,
            "modified": report.modified,
            "in_sync_count": len(report.in_sync),
        }
        print(json.dumps(out, indent=2))
    else:
        print(report.summary())

    return 1 if report.has_drift else 0
