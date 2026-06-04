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
import os
import sys
import time
import traceback
from pathlib import Path
from typing import List

import subprocess

from sentinel.core import RepoContext, ScanMode, Severity, Verdict
from sentinel.io import write_findings
from sentinel.io.git_files import set_path_filter
from sentinel.io.paths import SARIF_OUT
from sentinel.io.sarif import verdicts_to_sarif
from sentinel.registry.registry import Registry

RULES_ROOT = Path(__file__).parent.parent / "rules"
EXIT_INTERNAL_ERROR = 10
SARIF_FILENAME = SARIF_OUT
_PROJECT_INDEX_RELATIVE_CANDIDATES = (
    ("Projects", "projectindex-audit"),
    ("ProjectIndex",),
)


def _candidate_drive_roots() -> List[Path]:
    letters: List[str] = []
    system_drive = os.environ.get("SystemDrive", "")
    if len(system_drive) >= 1 and system_drive[0].isalpha():
        letters.append(system_drive[0].upper())
    for letter in ("C", "D"):
        if letter not in letters:
            letters.append(letter)
    return [Path(f"{letter}:" + os.sep) for letter in letters]


def _candidate_project_indexes() -> List[Path]:
    return [
        drive_root.joinpath(*rel_parts)
        for drive_root in _candidate_drive_roots()
        for rel_parts in _PROJECT_INDEX_RELATIVE_CANDIDATES
    ]


def _default_project_index() -> Path:
    candidates = _candidate_project_indexes()
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[0]


DEFAULT_PROJECT_INDEX = _default_project_index()


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
        default=DEFAULT_PROJECT_INDEX,
        help=f"Portfolio registry root (default: {DEFAULT_PROJECT_INDEX.as_posix()})",
    )
    p.add_argument("--json", action="store_true", help="Emit verdicts as JSON")
    p.add_argument(
        "--sarif", action="store_true",
        help=f"Also write findings to {SARIF_FILENAME} (SARIF 2.1.0; "
             "for GitHub code-scanning, GitLab SAST, IDE plugins).",
    )
    p.add_argument(
        "--timing", action="store_true",
        help="Print per-rule wall-clock timings to stdout. Off by default; "
             "intended for diagnosing which rule is the bottleneck.",
    )
    p.add_argument(
        "--diff", action="store_true",
        help="Only scan files changed vs --base-ref plus staged / "
             "unstaged / untracked. Sub-second on most PRs.",
    )
    p.add_argument(
        "--base-ref", default="HEAD",
        help="Base ref for --diff comparison (default HEAD — only "
             "uncommitted+untracked). Use 'origin/main' for PR-style "
             "'what's new on this branch' scans.",
    )
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

    # --diff: compute changed-file set, install as path filter for iter_repo_files.
    # The filter is module-level on sentinel.io.git_files; we clear it in finally.
    diff_filter_set = None
    if getattr(args, "diff", False) and args.repo:
        diff_filter_set = _collect_changed_files(args.repo, args.base_ref)
        if not diff_filter_set:
            print(
                f"[Sentinel] --diff: no changed files vs {args.base_ref} "
                "(plus staged/unstaged/untracked) — nothing to scan",
            )
            return 0
        print(
            f"[Sentinel] --diff: scanning {len(diff_filter_set)} changed "
            f"file(s) vs {args.base_ref}",
        )
        set_path_filter(frozenset(diff_filter_set))

    reg = Registry.from_dir(RULES_ROOT)

    verdicts: List[Verdict] = []
    timings: list[tuple[str, float]] = []
    try:
        for rule in reg.all_rules():
            if args.timing:
                t0 = time.perf_counter()
                verdicts.extend(rule.check(ctx))
                timings.append((rule.id, time.perf_counter() - t0))
            else:
                verdicts.extend(rule.check(ctx))
    finally:
        if diff_filter_set is not None:
            set_path_filter(None)

    write_findings(write_root, verdicts)

    if args.sarif:
        sarif_path = write_root / SARIF_FILENAME
        sarif_path.write_text(
            json.dumps(verdicts_to_sarif(verdicts), indent=2),
            encoding="utf-8",
        )

    if args.json:
        print(json.dumps({"verdicts": [v.to_dict() for v in verdicts]}, indent=2))
    else:
        _print_summary(verdicts)

    if args.timing:
        _print_timings(timings)

    return 1 if any(v.severity == Severity.BLOCK for v in verdicts) else 0


def _collect_changed_files(repo: Path, base_ref: str) -> set[str]:
    """Return the set of changed files (forward-slash relative paths) under
    `repo`, combining:
      - committed changes between `base_ref` and HEAD
      - staged changes (`git diff --cached`)
      - unstaged changes (`git diff`)
      - untracked-but-not-ignored files (`git ls-files --others
        --exclude-standard`)

    Any individual command failing (e.g. base_ref doesn't exist) is
    skipped — other sources still contribute. Returns empty set on
    full failure rather than raising.
    """
    out: set[str] = set()
    cmds: list[list[str]] = [
        ["git", "-C", str(repo), "diff", "--name-only", f"{base_ref}...HEAD"],
        ["git", "-C", str(repo), "diff", "--name-only"],
        ["git", "-C", str(repo), "diff", "--name-only", "--cached"],
        ["git", "-C", str(repo), "ls-files", "--others", "--exclude-standard"],
    ]
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if r.returncode != 0:
            continue
        for line in r.stdout.splitlines():
            line = line.strip().replace("\\", "/")
            if line:
                out.add(line)
    return out


def _print_timings(timings: list[tuple[str, float]]) -> None:
    """Print per-rule timings sorted slowest-first, plus a total line.
    Format kept tabular for grep-ability; never localized."""
    if not timings:
        return
    total = sum(d for _, d in timings)
    for rule_id, dur in sorted(timings, key=lambda t: t[1], reverse=True):
        print(f"[timing]  {rule_id:<40}  {dur:.3f}s")
    print(f"[timing]  {'TOTAL':<40}  {total:.3f}s")


def _print_summary(verdicts: List[Verdict]) -> None:
    block = sum(1 for v in verdicts if v.severity == Severity.BLOCK)
    warn = sum(1 for v in verdicts if v.severity == Severity.WARN)
    info = sum(1 for v in verdicts if v.severity == Severity.INFO)
    print(f"[Sentinel] verdicts: BLOCK={block} WARN={warn} INFO={info}")
    for v in verdicts:
        loc = f"{v.file}:{v.line}" if v.file and v.line else v.file or "(repo-wide)"
        print(f"  [{v.severity.label}] {v.rule_id}  {loc}  {v.detail[:80]}")
