"""`sentinel scan` subcommand.

Exit code contract (contract with hook/payload.py):
  0   clean — no BLOCK verdicts
  1   findings — at least one BLOCK verdict
  2   user error — missing/non-git repo, bad CLI args
  10  internal error — scan itself crashed (ImportError, uncaught exception).
       Hook MUST fail-closed on this, regardless of warn/block mode.
       Rationale: a crashed scan has NOT validated the push. Treating it as
       "clean" (exit 0) or "findings" (warn-able) lets broken Sentinel silently
       stop enforcing across the portfolio.
"""
from __future__ import annotations
import argparse
import json
import sys
import traceback
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, ScanMode, Severity, Verdict
from sentinel.io import write_findings
from sentinel.registry.registry import Registry

RULES_ROOT = Path(__file__).parent.parent / "rules"
EXIT_INTERNAL_ERROR = 10


def add_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("scan", help="Scan a repo or the portfolio")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--repo", type=Path, help="Scan a single repository")
    group.add_argument(
        "--portfolio", action="store_true",
        help="Scan the portfolio (requires --project-index)",
    )
    p.add_argument(
        "--project-index", type=Path,
        default=Path("C:/ProjectIndex"),
        help="Portfolio registry root (default: C:/ProjectIndex)",
    )
    p.add_argument("--json", action="store_true", help="Emit verdicts as JSON")
    p.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> int:
    try:
        return _run_inner(args)
    except Exception as e:
        print(
            f"[Sentinel] INTERNAL ERROR: {type(e).__name__}: {e}",
            file=sys.stderr,
        )
        print("--- traceback ---", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        print(
            f"[Sentinel] scan crashed (exit {EXIT_INTERNAL_ERROR}). Fix Sentinel "
            f"before next push, or use SENTINEL_BYPASS=1 to push anyway. "
            f"This is NOT a clean scan — no verdicts were produced.",
            file=sys.stderr,
        )
        return EXIT_INTERNAL_ERROR


def _run_inner(args: argparse.Namespace) -> int:
    if args.repo:
        if not args.repo.is_dir():
            print(
                f"[Sentinel] error: --repo path does not exist or is not a "
                f"directory: {args.repo}",
                file=sys.stderr,
            )
            return 2
        if not (args.repo / ".git").is_dir():
            print(
                f"[Sentinel] error: --repo is not a git repository "
                f"(no .git/ dir): {args.repo}",
                file=sys.stderr,
            )
            return 2
        ctx = RepoContext(repo_root=args.repo, mode=ScanMode.REPO)
        write_root = args.repo
    else:
        if not args.project_index.is_dir():
            print(
                f"[Sentinel] error: --project-index path does not exist: "
                f"{args.project_index}",
                file=sys.stderr,
            )
            return 2
        ctx = RepoContext(
            repo_root=args.project_index,
            mode=ScanMode.PORTFOLIO,
            project_index_root=args.project_index,
        )
        write_root = args.project_index

    reg = Registry.from_dir(RULES_ROOT)

    verdicts: List[Verdict] = []
    for rule in reg.all_rules():
        verdicts.extend(rule.check(ctx))

    write_findings(write_root, verdicts)

    if args.json:
        print(json.dumps({"verdicts": [v.to_dict() for v in verdicts]}, indent=2))
    else:
        _print_summary(verdicts)

    return 1 if any(v.severity == Severity.BLOCK for v in verdicts) else 0


def _print_summary(verdicts: List[Verdict]) -> None:
    block = sum(1 for v in verdicts if v.severity == Severity.BLOCK)
    warn = sum(1 for v in verdicts if v.severity == Severity.WARN)
    info = sum(1 for v in verdicts if v.severity == Severity.INFO)
    print(f"[Sentinel] verdicts: BLOCK={block} WARN={warn} INFO={info}")
    for v in verdicts:
        loc = f"{v.file}:{v.line}" if v.file and v.line else v.file or "(repo-wide)"
        print(f"  [{v.severity.label}] {v.rule_id}  {loc}  {v.detail[:80]}")
