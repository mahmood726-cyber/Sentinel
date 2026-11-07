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
import re
import sys
import time
import traceback
from pathlib import Path
from datetime import datetime, timezone
from typing import List

import subprocess

from sentinel.core import RepoContext, ScanMode, Severity, Verdict
from sentinel.io import write_findings
from sentinel.io.git_files import (
    has_undecodable_name,
    printable_path,
    set_path_filter,
)
from sentinel.io.paths import SARIF_OUT
from sentinel.io.sarif import verdicts_to_sarif
from sentinel.registry.registry import Registry

RULES_ROOT = Path(__file__).parent.parent / "rules"
EXIT_INTERNAL_ERROR = 10
NOT_SCANNED_RULE_ID = "SENTINEL-not-scanned"
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
        # Linked Git worktrees and submodules store a .git *file* that
        # points to their actual Git directory. File discovery already
        # recognizes this shape; the CLI must not reject it before scanning.
        if not (args.repo / ".git").exists():
            print(
                f"[Sentinel] error: --repo is not a git repository "
                f"(no .git directory or worktree marker): {args.repo}",
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
        if diff_filter_set is None:
            # An invalid base, failed git subprocess or timeout must not
            # masquerade as a clean diff. A partial changed-file set can
            # miss committed BLOCK findings, so scan the whole repository.
            print(
                "[Sentinel] --diff: git change probe failed; "
                "falling back to full scan",
            )
        elif not diff_filter_set:
            print(
                f"[Sentinel] --diff: no changed files vs {args.base_ref} "
                "(plus staged/unstaged/untracked) — nothing to scan",
            )
            # Emit the verdicts marker so callers (e.g. the pre-push hook's
            # proof-of-run check) can tell a clean no-op from a crash. A push
            # with no scannable files — notably a branch/tag DELETION — is a
            # legitimate 0-findings pass, not a Sentinel crash.
            _print_summary([])
            return 0
        else:
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

    # A file no rule could read is reported, never dropped: --json prints no
    # scope line, so it has to travel as a verdict as well.
    not_scanned = _not_scanned_paths(ctx, diff_filter_set)
    verdicts.extend(_not_scanned_verdicts(ctx, not_scanned))

    write_findings(write_root, verdicts)

    if args.sarif:
        sarif_path = write_root / SARIF_FILENAME
        sarif_path.write_text(
            json.dumps(verdicts_to_sarif(verdicts), indent=2),
            encoding="utf-8",
        )

    if not args.json:
        _print_scope(
            ctx, diff_filter_set, getattr(args, 'base_ref', None), not_scanned,
        )
        _print_coverage(ctx)

    if args.json:
        print(json.dumps({"verdicts": [v.to_dict() for v in verdicts]}, indent=2))
    else:
        _print_summary(verdicts)

    if args.timing:
        _print_timings(timings)

    return 1 if any(v.severity == Severity.BLOCK for v in verdicts) else 0


def _rule_population_census(rules_root: Path) -> dict:
    """Which file population each rule reads, measured from the discovery call
    it actually makes rather than from a declaration it does not yet carry.

    This is a static read of the plugin sources. It is deliberately crude and
    deliberately printed: the point is that the four populations exist and were
    invisible, not that this classifier is subtle.
    """
    counts = {"PUBLISHED": 0, "PRESENT": 0, "DISK": 0, "no-walk": 0,
              "declared": 0, "undeclared": 0}
    plugins = rules_root / "plugins"
    if plugins.is_dir():
        for p in sorted(plugins.glob("*.py")):
            if p.stem == "__init__":
                continue
            try:
                src = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # A DECLARED population wins over inference. Undeclared rules are
            # counted by the discovery call they make, and reported as
            # undeclared so the opt-in progress is visible rather than assumed.
            # Match DECLARATIONS, not substrings. A comment that mentions
            # POPULATION_EXEMPT or os.walk while explaining that the rule no
            # longer uses them re-triggered this census and kept reporting a
            # rule as exempt after it had been migrated. Third instance today
            # of a detector matching the text that DESCRIBES the thing it
            # looks for, so: strip comments, then anchor on an assignment.
            code = re.sub(r"(?m)^\s*#.*$", "", src)
            if re.search(r"(?m)^POPULATION_EXEMPT\s*=", code):
                counts["declared"] += 1
                counts["hybrid"] = counts.get("hybrid", 0) + 1
                continue
            m = re.search(r"^POPULATION\s*=\s*Population\.(\w+)", code, re.M)
            if m:
                counts["declared"] += 1
                counts[m.group(1)] = counts.get(m.group(1), 0) + 1
            elif "iter_repo_files" in code:
                counts["PUBLISHED"] += 1
                counts["undeclared"] += 1
            elif ("iter_tree_or_filter" in code or ".rglob(" in code
                  or "os.walk(" in code):
                counts["DISK"] += 1
                counts["undeclared"] += 1
            else:
                counts["no-walk"] += 1
    yaml_dir = rules_root / "yaml"
    if yaml_dir.is_dir():
        counts["n_yaml"] = len(list(yaml_dir.glob("*.yaml")))
    return counts


def _not_scanned_paths(ctx: "RepoContext", diff_filter) -> List[str]:
    """Files in this scan's scope that no rule could read.

    Measured from the population rather than collected from the rules, so a
    rule whose patterns happen not to match still leaves the file counted.
    """
    from sentinel.io.population import repo_files, Population
    present = repo_files(ctx.repo_root, Population.PRESENT) or frozenset()
    in_scope = present if diff_filter is None else present & diff_filter
    return sorted(rel for rel in in_scope if has_undecodable_name(rel))


def _not_scanned_verdicts(ctx: "RepoContext", rels: List[str]) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    return [
        Verdict(
            rule_id=NOT_SCANNED_RULE_ID,
            severity=Severity.WARN,
            repo=str(ctx.repo_root),
            file=printable_path(rel),
            line=None,
            detail="file name is not valid UTF-8; no rule read this file",
            fix_hint="rename the file to a UTF-8 name so that it can be scanned",
            source="sentinel/cli/scan.py",
            timestamp=now,
        )
        for rel in rels
    ]


def _print_scope(ctx: "RepoContext", diff_filter, base_ref, not_scanned=()) -> None:
    """State the SCAN SCOPE before any count, because a count over a subset is
    not a count over the repo.

    Measured 2026-08-30 on F:/E156: the pre-push default auto-detects
    origin/HEAD and scans the changed+untracked set -- 614 of 4,246 files,
    14.5% of the repo. A scan in that mode reported "155 BLOCK / 1,900 WARN";
    the same tree scanned whole reports 76 BLOCK / 3,732 WARN. The WARN tier
    was under-reported by nearly half, and nothing in the output said the
    number described a seventh of the repo.

    `not_scanned` stays in the denominator and leaves the numerator.
    """
    try:
        from sentinel.io.population import repo_files, Population
        present = repo_files(ctx.repo_root, Population.PRESENT)
        total = len(present) if present is not None else None
    except Exception:  # noqa: BLE001
        total = None
    skipped = len(not_scanned)
    if diff_filter is None:
        if total:
            scanned = total - skipped
            share = f"{100.0 * scanned / total:.1f}%" if skipped else "100%"
            print(f"[Sentinel] scope: FULL TREE - {scanned} of {total} files ({share})")
        else:
            print("[Sentinel] scope: FULL TREE")
    else:
        n = len(diff_filter) - skipped
        if total:
            pct = 100.0 * n / total
            print(f"[Sentinel] scope: --diff vs {base_ref} - {n} of {total} files "
                  f"({pct:.1f}%) - counts below are for this subset, NOT the repo")
        else:
            print(f"[Sentinel] scope: --diff vs {base_ref} - {n} files - counts "
                  f"below are for this subset, NOT the repo")
    if skipped:
        shown = ", ".join(printable_path(rel) for rel in not_scanned[:10])
        more = f" and {skipped - 10} more" if skipped > 10 else ""
        print(f"[Sentinel] NOT SCANNED: {skipped} file(s) with a non-UTF-8 name, "
              f"read by no rule: {shown}{more}")


def _print_coverage(ctx: "RepoContext") -> None:
    """Publish the file population every rule family reads. Never raises: a
    coverage line that can abort a scan would be worse than no coverage line."""
    try:
        from sentinel.io.population import coverage
        cov = coverage(ctx.repo_root)
        census = _rule_population_census(RULES_ROOT)
        n_yaml = census.pop("n_yaml", 0)
    except Exception as e:  # noqa: BLE001
        print(f"[Sentinel] coverage: unavailable ({type(e).__name__}: {e})")
        return
    if not cov.get("git"):
        print("[Sentinel] coverage: not a git worktree - rules fall back to a "
              "bounded filesystem walk; population is unbounded")
    else:
        print(
            f"[Sentinel] population: PUBLISHED(tracked)={cov['published']}  "
            f"PRESENT(+untracked-not-ignored)={cov['present']}  "
            f"present-only={cov['present_only']}"
        )
    total = (census["PUBLISHED"] + census["PRESENT"] + census["DISK"]
             + census["no-walk"] + census.get("hybrid", 0) + n_yaml)
    print(
        f"[Sentinel] rules read: PUBLISHED={census['PUBLISHED']} "
        f"PRESENT={census['PRESENT']} DISK={census['DISK']} "
        f"no-walk={census['no-walk']} hybrid={census.get('hybrid', 0)} "
        f"(+{n_yaml} yaml)"
    )
    print(
        f"[Sentinel] population declared by {census['declared']} of {total} "
        f"rules; {census['undeclared']} still inferred from their discovery "
        f"call" + ("  <-- an inferred population is an assumption, not a "
                   "declaration" if census["undeclared"] else "")
    )


def _collect_changed_files(repo: Path, base_ref: str) -> set[str] | None:
    """Collect changed paths, or None when a git probe cannot be trusted.

    Combine committed changes vs base_ref, unstaged, staged and untracked
    files. A failed command (including an invalid base ref) makes the
    result incomplete: return None to force a full scan, never an empty
    or partial set that could silently drop a committed BLOCK finding.
    """
    out: set[str] = set()
    # -z is required: without it Git C-quotes Unicode/tab/newline paths,
    # and splitlines()/strip() silently change legitimate filenames. Exact
    # path identity is required for --diff filtering to preserve BLOCKs.
    cmds: list[list[str]] = [
        ["git", "-C", str(repo), "diff", "--name-only", "-z", f"{base_ref}...HEAD"],
        ["git", "-C", str(repo), "diff", "--name-only", "-z"],
        ["git", "-C", str(repo), "diff", "--name-only", "-z", "--cached"],
        ["git", "-C", str(repo), "ls-files", "-z", "--others", "--exclude-standard"],
    ]
    for cmd in cmds:
        try:
            # Git -z emits UTF-8 path bytes; Windows' locale codec can
            # otherwise decode names differently from the filesystem.
            # surrogateescape keeps a non-UTF-8 name in the set; it must not
            # crash the probe, because that blocks every push of the repo.
            r = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8",
                errors="surrogateescape", timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if r.returncode != 0:
            return None
        for rel in r.stdout.split("\x00"):
            if rel:
                out.add(rel)
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
