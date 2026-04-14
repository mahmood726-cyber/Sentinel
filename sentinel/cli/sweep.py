"""`sentinel sweep` — scan multiple repos, emit a single JSON summary."""
from __future__ import annotations
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.registry import Registry

RULES_ROOT = Path(__file__).parent.parent / "rules"


def add_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("sweep", help="Scan multiple repos and emit JSON summary")
    p.add_argument("--repos", action="append", required=True, type=Path,
                   help="Repo path (repeat for multiple)")
    p.add_argument("--out", required=True, type=Path, help="Output JSON path")
    p.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> int:
    reg = Registry.from_dir(RULES_ROOT)
    per_repo = []
    total = {"BLOCK": 0, "WARN": 0, "INFO": 0}

    for repo in args.repos:
        ctx = RepoContext(repo_root=repo, mode=ScanMode.REPO)
        verdicts = []
        for rule in reg.all_rules():
            verdicts.extend(rule.check(ctx))
        counts = {"BLOCK": 0, "WARN": 0, "INFO": 0}
        for v in verdicts:
            counts[v.severity.label] += 1
            total[v.severity.label] += 1
        per_repo.append({
            "repo": str(repo),
            "counts": counts,
            "verdicts": [v.to_dict() for v in verdicts],
        })

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repos_scanned": len(args.repos),
        "total_counts": total,
        "per_repo": per_repo,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[Sentinel sweep] {len(args.repos)} repos  BLOCK={total['BLOCK']} "
          f"WARN={total['WARN']} INFO={total['INFO']}  -> {args.out}")
    return 0
