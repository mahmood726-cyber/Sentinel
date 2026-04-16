"""P1-py-parse-check: BLOCK pushes containing .py files that fail python's parser.

Parallel to P1-js-parse-check (2026-04-15). Catches Python SyntaxErrors
(malformed f-strings, unmatched brackets, bad indentation) before they
reach a submission-ready state.

Triggering incident: saarc-e156-students 2026-04-16. Six generator
scripts across 3 paper groups had the pattern
  `print(f"  {'Karachi's Global Trial Share'}")`
— the inner single-quote terminated the inner string, producing
SyntaxError on any attempt to import or run the file. They sat on disk
unmodified for weeks because no one ever ran them. A parse-check at
push time would have surfaced the bug on commit day.

Implementation: shell out to `python -m py_compile <file>` per candidate.
Cost: ~30-80ms per file (interpreter startup dominates). A 200-file repo
adds ~10s to pre-push — outside Sentinel's ideal sub-5-second budget
but acceptable for a BLOCK-severity correctness rule.

Excludes: virtual envs, build output, test caches, and site-packages.
"""
from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P1-py-parse-check"
SEVERITY = Severity.BLOCK
SOURCE = "lessons.md#python-module-test-collection-traps"
SCOPE = "repo"

EXCLUDE_DIRS = {
    "__pycache__", ".venv", "venv", ".git", "node_modules", "dist",
    "build", ".pytest_cache", "site-packages", ".tox", ".eggs",
    "htmlcov", "playwright-report", "test-results",
}


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []

    for path in _iter_py_files(ctx.repo_root):
        rel = path.relative_to(ctx.repo_root).as_posix()
        try:
            result = subprocess.run(
                [sys.executable, "-m", "py_compile", str(path)],
                capture_output=True, text=True, timeout=10,
            )
        except subprocess.TimeoutExpired:
            verdicts.append(Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(ctx.repo_root),
                file=rel,
                line=None,
                detail="py_compile timed out after 10s",
                fix_hint=f"investigate why compiling {rel} is slow",
                source=SOURCE,
                timestamp=now,
            ))
            continue

        if result.returncode != 0:
            stderr_lines = (result.stderr or "").strip().splitlines()
            # py_compile prints multi-line errors; first few lines usually
            # include the SyntaxError message and offending-line pointer.
            detail = " | ".join(stderr_lines[:3]) if stderr_lines else "py_compile failed"
            verdicts.append(Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(ctx.repo_root),
                file=rel,
                line=None,
                detail=detail[:300],
                fix_hint=f"run `python -m py_compile {rel}` locally and fix the syntax error",
                source=SOURCE,
                timestamp=now,
            ))

    return verdicts


def _iter_py_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*.py"):
        if not path.is_file():
            continue
        if any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        yield path
