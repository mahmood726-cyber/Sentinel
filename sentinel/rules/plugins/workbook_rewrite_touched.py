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

# Kept so callers/tests referencing the legacy literal still resolve. The rule
# itself matches on REWRITE_HEADER_RE below.
REWRITE_HEADER = "YOUR REWRITE:"

# 2026-08-30. This rule guards the one non-negotiable contract in the project
# ("YOUR REWRITE is the author's; never touch it") and it was matching an
# EXACT-PREFIX LITERAL against a header that carries a parenthetical:
#
#   "YOUR REWRITE (at most 156 words, 7 sentences):".startswith("YOUR REWRITE:")
#   -> False
#
# Measured on the live workbook: 1,864 entries use the parenthetical form, 11
# use the bare colon. The rule therefore protected 11 of 1,875 blocks (0.6%),
# covering 65 of 122,369 lines (0.1%) -- and reported green over that sliver.
# Not a dead check: a LIVE check passing on a 0.1% sample. A literal where a
# structure was needed.
#
# Structure matches both spellings: 1,875 / 1,875 blocks, 97,529 / 122,369
# lines (79.7%).
REWRITE_HEADER_RE = re.compile(r"^YOUR REWRITE\b[^\n]*:\s*$")

# A protected range ends at the first of these. `SUBMISSION METADATA:` was
# missing and is the real terminator: it is the first metadata key after the
# header in 1,729 of the 1,859 entries that have one (a `===` separator in 124,
# `SUBMITTED:` in 6). Without it a protected range swallows the whole
# submission-metadata trailer, so every legitimate publish commit -- which
# appends an `OJS:` line and flips `SUBMITTED: [ ]` to `[x]` inside that
# trailer -- would BLOCK. Fixing the header WITHOUT fixing the boundary would
# turn a rule that guards almost nothing into one that fires on almost every
# publish, which is the worse defect one step down.
BLOCK_TERMINATORS = (
    "SUBMISSION METADATA:", "SUBMITTED:", "CURRENT BODY", "ENTRY ", "---",
    "Target journal:", "Manuscript license:", "Code license:", "OJS:",
    "Preprint:", "Protocol:", "=" * 50,
)


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
        if REWRITE_HEADER_RE.match(stripped):
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
