# sentinel:skip-file — docstring example contains the bad pattern.
"""P2-todo-past-date: WARN on TODO/FIXME/HACK markers whose written-in
date has passed.

The deferred-work problem: operators leave `TODO(2026-03-15): remove
this shim` markers with the intent to clean up by that date. Then the
date passes silently. The marker becomes invisible — code-review tools
treat it as a regular TODO. This rule re-surfaces TODOs whose date is
in the past.

Patterns matched:

    TODO(2026-03-15): legacy alias
    FIXME(2026-03-15) — drop after migration
    HACK 2026-03-15  workaround for #1234
    # TODO 2025-12-01: remove deprecation shim

Date forms accepted: `YYYY-MM-DD` only (the unambiguous ISO format).
`MM/DD/YYYY` / `DD/MM/YYYY` are skipped because the locale ambiguity
creates false positives.

Severity is INFO, not WARN, by default — these are not bugs, they
are scheduled work that the operator chose to defer. They should
be visible to PR review but should not block pushes.

The rule respects per-line `sentinel:skip-line P2-todo-past-date`
markers for operators who want to formally extend a deadline by
explicit annotation.
"""
from __future__ import annotations

import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import iter_repo_files
from sentinel.io.skip_marker import has_skip_marker, line_is_suppressed


ID = "P2-todo-past-date"
SEVERITY = Severity.INFO
SOURCE = ("rules.md  (test/instrumentation with 'remove after X' "
          "condition; TODOs with explicit dates surface deferred work)")
SCOPE = "repo"

MAX_FILE_BYTES = 2_000_000
TEXT_EXCLUDE_DIRS = (".venv", "venv", "__pycache__", "build", "dist",
                     ".tox", ".pytest_cache", "node_modules", "archive",
                     ".git", "site-packages")
TEXT_EXTENSIONS = ("*.py", "*.md", "*.html", "*.htm", "*.js", "*.mjs",
                   "*.cjs", "*.ts", "*.yaml", "*.yml", "*.txt", "*.rst",
                   "*.toml", "*.r", "*.R", "*.sh", "*.bat", "*.ps1")

# TODO/FIXME/HACK/XXX followed by an ISO date, with the date in a
# bracket / paren / colon / space context. The date is captured.
_MARKER_RE = re.compile(
    r"\b(TODO|FIXME|HACK|XXX)\s*[\(\[\s:]*\s*(\d{4})-(\d{2})-(\d{2})\b",
    re.IGNORECASE,
)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    today = now.date()
    verdicts: List[Verdict] = []
    root = ctx.repo_root
    for path in iter_repo_files(root, TEXT_EXTENSIONS, TEXT_EXCLUDE_DIRS):
        if has_skip_marker(path):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Cheap pre-filter: skip files without any marker keyword.
        if not any(k in text for k in ("TODO", "FIXME", "HACK", "XXX",
                                       "todo", "fixme")):
            continue
        rel = path.relative_to(root).as_posix()
        lines = text.splitlines()
        seen_offsets: set[int] = set()
        for m in _MARKER_RE.finditer(text):
            keyword = m.group(1).upper()
            try:
                d = date(int(m.group(2)), int(m.group(3)), int(m.group(4)))
            except ValueError:
                continue  # invalid date (e.g. 2026-02-31)
            if d >= today:
                continue  # future or today — not yet overdue
            if m.start() in seen_offsets:
                continue
            seen_offsets.add(m.start())
            line_no = _line_of(text, m.start())
            cur = lines[line_no - 1] if line_no - 1 < len(lines) else ""
            prv = lines[line_no - 2] if line_no - 2 >= 0 else ""
            if line_is_suppressed(cur, prv, ID):
                continue
            days_overdue = (today - d).days
            verdicts.append(Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(root),
                file=rel,
                line=line_no,
                detail=(
                    f"{keyword}({d.isoformat()}) is {days_overdue} day(s) "
                    "overdue — scheduled cleanup deadline has passed"
                ),
                fix_hint=(
                    "either action the deferred work, push the date "
                    "forward with rationale, or add "
                    "`# sentinel:skip-line P2-todo-past-date` to "
                    "formally extend the deadline"
                ),
                source=SOURCE,
                timestamp=now,
            ))
    return verdicts
