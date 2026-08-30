# sentinel:skip-file — docstring example contains the bad pattern.
"""P2-numeric-parse-or-null: WARN on `parseFloat(x) || null` /
`parseInt(x) || null` / `Number(x) || null` — drops 0.0 silently.

Past incident (lessons.md "`parseFloat(x) || null` drops 0.0"):

    const value = parseFloat(input) || null;   // BAD: parseFloat("0") = 0, falsy → null

When the parsed value is `0` or `0.0`, JavaScript's `||` operator
treats it as falsy and returns the right-hand side instead. For
numeric data this silently corrupts zero values. The fix:

    const parsed = parseFloat(input);
    const value = Number.isFinite(parsed) ? parsed : null;

Or with the nullish-coalescing operator, narrower in intent:

    const value = parseFloat(input) ?? null;   // OK — only catches NaN/null/undefined
    // (but `??` doesn't catch NaN either, so `Number.isFinite()` is the safer form)
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import iter_repo_files
from sentinel.io.population import Population
from sentinel.io.skip_marker import has_skip_marker


ID = "P2-numeric-parse-or-null"
SEVERITY = Severity.WARN
SOURCE = "lessons.md#javascript--html  (parseFloat(x) || null drops 0.0)"
SCOPE = "repo"

# Population: PRESENT -- tracked AND untracked-not-ignored. This is a
# CORRECTNESS rule: the defect it finds runs when someone runs the file,
# whether or not git is tracking it. Migrated 2026-08-30; counts from
# before that date were taken over the tracked set only and are NOT
# comparable with counts after it.
POPULATION = Population.PRESENT

MAX_FILE_BYTES = 5_000_000
JS_EXCLUDE_DIRS = (".venv", "venv", "__pycache__", "node_modules", "dist",
                   "build", ".pytest_cache", ".next", "out")

# `parseFloat(...) || X` / `parseInt(...) || X` / `Number(...) || X`
# where X is null / undefined / 0 / 0.0. Allow whitespace.
_BAD_RE = re.compile(
    r"\b(?:parseFloat|parseInt|Number)\s*\([^)]*\)\s*\|\|\s*(null|undefined|0(?:\.0+)?)\b"
)

# Strip comments + string literals to avoid false positives on bad-pattern
# strings (e.g. docstrings, regex tests).
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_LITERAL_RE = re.compile(r"`(?:\\.|[^`\\])*`|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'")


def _strip_noise(text: str) -> str:
    def _ws(m):
        return " " * (m.end() - m.start())
    text = _BLOCK_COMMENT_RE.sub(_ws, text)
    text = _LINE_COMMENT_RE.sub(_ws, text)
    text = _STRING_LITERAL_RE.sub(_ws, text)
    return text


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


_SCRIPT_BODY_RE = re.compile(
    r"<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script\s*>",
    re.IGNORECASE | re.DOTALL,
)


def _scan(text: str, rel: str, root: Path, now: datetime,
          line_offset: int = 0) -> List[Verdict]:
    out: List[Verdict] = []
    stripped = _strip_noise(text)
    for m in _BAD_RE.finditer(stripped):
        out.append(Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=str(root),
            file=rel,
            line=_line_of(text, m.start()) + line_offset,
            detail=(
                f"`{m.group(0)[:60]}` drops 0/0.0 silently — parsed zero "
                "is falsy and falls through to the right-hand fallback"
            ),
            fix_hint=(
                "use `Number.isFinite(parsed) ? parsed : null` after a "
                "single parseFloat/parseInt/Number call"
            ),
            source=SOURCE,
            timestamp=now,
        ))
    return out


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    root = ctx.repo_root

    for path in iter_repo_files(root, ("*.js", "*.mjs", "*.cjs", "*.ts"),
                                JS_EXCLUDE_DIRS, population=POPULATION):
        if has_skip_marker(path):
            continue
        if path.name.endswith(".min.js"):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not any(tok in text for tok in ("parseFloat", "parseInt", "Number(")):
            continue
        rel = path.relative_to(root).as_posix()
        verdicts.extend(_scan(text, rel, root, now))

    for path in iter_repo_files(root, ("*.html", "*.htm"), JS_EXCLUDE_DIRS, population=POPULATION):
        if has_skip_marker(path):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not any(tok in text for tok in ("parseFloat", "parseInt", "Number(")):
            continue
        rel = path.relative_to(root).as_posix()
        for m in _SCRIPT_BODY_RE.finditer(text):
            body_start_line = _line_of(text, m.start(1)) - 1
            verdicts.extend(_scan(m.group(1), rel, root, now,
                                  line_offset=body_start_line))
    return verdicts
