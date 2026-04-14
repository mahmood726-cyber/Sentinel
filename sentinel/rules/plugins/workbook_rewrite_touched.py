"""P0-workbook-rewrite-touched: BLOCK if a staged diff touches a
YOUR REWRITE: section in rewrite-workbook.txt.

Testing aid: honors env var SENTINEL_TEST_DIFF to bypass git invocation."""
from __future__ import annotations
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Set

from sentinel.core import RepoContext, Severity, Verdict


ID = "P0-workbook-rewrite-touched"
SEVERITY = Severity.BLOCK
SOURCE = "CLAUDE.md#workbook-protection"
SCOPE = "repo"

WORKBOOK_BASENAME = "rewrite-workbook.txt"
REWRITE_HEADER = "YOUR REWRITE:"
BLOCK_TERMINATORS = ("SUBMITTED:", "CURRENT BODY:", "ENTRY ", "---")


def _protected_line_ranges(workbook_text: str) -> List[tuple]:
    """Return list of (start_line, end_line) 1-indexed ranges, inclusive.

    Each range covers the content lines inside a YOUR REWRITE: block,
    i.e. the line AFTER the header up to (but not including) the next
    block terminator line.
    """
    lines = workbook_text.splitlines()
    ranges: List[tuple] = []
    in_rewrite = False
    start = None
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith(REWRITE_HEADER):
            in_rewrite = True
            start = idx + 1  # content starts on the next line
            continue
        if in_rewrite and any(stripped.startswith(t) for t in BLOCK_TERMINATORS):
            if start is not None:
                ranges.append((start, idx - 1))
            in_rewrite = False
            start = None
    # Handle a rewrite block at end-of-file with no terminator
    if in_rewrite and start is not None:
        ranges.append((start, len(lines)))
    return ranges


_HUNK_RE = re.compile(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@')


def _touched_lines_in_workbook(diff_text: str) -> Set[int]:
    """Parse a unified diff and return 1-indexed new-file line numbers touched
    within the rewrite-workbook.txt section.

    Only '+' lines (additions) advance the new-file counter and are recorded.
    '-' lines (deletions) do NOT advance the new-file counter.
    Context lines (' ') advance the counter but are not recorded.
    """
    touched: Set[int] = set()
    in_workbook = False
    current_line = 0
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            in_workbook = WORKBOOK_BASENAME in line
            continue
        if not in_workbook:
            continue
        m = _HUNK_RE.match(line)
        if m:
            current_line = int(m.group(1))
            continue
        if line.startswith("+") and not line.startswith("+++"):
            touched.add(current_line)
            current_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            pass  # deletions don't advance the new-file counter
        elif line.startswith(" "):
            current_line += 1
    return touched


def _get_diff(repo_root: Path) -> str:
    """Return the diff text. In tests, SENTINEL_TEST_DIFF env var takes
    precedence over running git. In production, runs git diff --cached."""
    override = os.environ.get("SENTINEL_TEST_DIFF")
    if override is not None:
        return override
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--unified=0"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""
    return result.stdout


def check(ctx: RepoContext) -> List[Verdict]:
    workbook = ctx.repo_root / WORKBOOK_BASENAME
    if not workbook.is_file():
        return []
    workbook_text = workbook.read_text(encoding="utf-8", errors="replace")
    protected = _protected_line_ranges(workbook_text)
    if not protected:
        return []

    diff_text = _get_diff(ctx.repo_root)
    touched = _touched_lines_in_workbook(diff_text)
    if not touched:
        return []

    hits = [
        line for line in touched
        if any(start <= line <= end for start, end in protected)
    ]
    if not hits:
        return []

    return [
        Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=str(ctx.repo_root),
            file=WORKBOOK_BASENAME,
            line=min(hits),
            detail=(
                f"staged diff touches protected YOUR REWRITE: section "
                f"at lines {sorted(hits)}"
            ),
            fix_hint=(
                "The YOUR REWRITE: block is sacrosanct per CLAUDE.md. "
                "Revert those lines and commit only CURRENT BODY changes. "
                "If the user authorized the rewrite edit, bypass Sentinel "
                "for this push with SENTINEL_BYPASS=1."
            ),
            source=SOURCE,
            timestamp=datetime.now(timezone.utc),
        )
    ]
