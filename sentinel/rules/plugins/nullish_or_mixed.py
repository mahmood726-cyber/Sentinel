# sentinel:skip-file — docstring example contains the bad pattern.
"""P1-nullish-or-mixed: BLOCK on `?? ... ||` (or vice versa) mixed
in JavaScript without explicit grouping parentheses.

Past incident (lessons.md "`?? ... ||` mixing: SyntaxError"): JavaScript
forbids un-parenthesised mixing of the nullish-coalescing operator (`??`)
with logical OR (`||`) or logical AND (`&&`) in the same expression.
The bad form raises `SyntaxError: Unexpected token '||'` at parse time:

    const x = a ?? b || c;            // SyntaxError
    const y = a || b ?? c;            // SyntaxError

The fix is one of:

    const x = a ?? (b || c);          // OK
    const x = (a ?? b) || c;          // OK

The rule scans every tracked .js / .mjs / .cjs / .ts file plus inline
<script> blocks in .html files. Detection is line-scoped: a single line
containing `??` AND `||` (or `&&`) without enclosing parentheses between
the two operators trips the BLOCK.
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


ID = "P1-nullish-or-mixed"
SEVERITY = Severity.BLOCK
SOURCE = "lessons.md#javascript--html  (?? ... || mixing — SyntaxError)"
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

# Capture `a ?? b || c` or `a ?? b && c` (and the reverse) — but only
# when neither side is wrapped in its own parentheses. A `?? || `
# sequence between two parens is an explicit-grouping shape we should
# NOT flag (`(a || b) ?? c` is legal).
_MIX_RE = re.compile(
    r"(?<![?(])\?\?(?![?])\s*[A-Za-z0-9_.\[\]'\"`+\-*/%\s$]+?\s*(?:\|\||&&)"
    r"|(?:\|\||&&)\s*[A-Za-z0-9_.\[\]'\"`+\-*/%\s$]+?\s*(?<![?(])\?\?(?![?])"
)

# Strip JS line-comments and block-comments before scanning.
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_LITERAL_RE = re.compile(r"`(?:\\.|[^`\\])*`|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'")


def _strip_noise(text: str) -> str:
    """Replace comments + string literals with same-length whitespace so line
    numbers + offsets stay stable, while the regex can't match inside them."""
    def _ws(m):
        return " " * (m.end() - m.start())
    text = _BLOCK_COMMENT_RE.sub(_ws, text)
    text = _LINE_COMMENT_RE.sub(_ws, text)
    text = _STRING_LITERAL_RE.sub(_ws, text)
    return text


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _scan(text: str, rel: str, root: Path, now: datetime) -> List[Verdict]:
    """Scan a JS text body. Strips comments + string literals, then
    finds un-parenthesised `?? + ||/&&` mixes on a single line."""
    out: List[Verdict] = []
    stripped = _strip_noise(text)
    for m in _MIX_RE.finditer(stripped):
        # Per-match: ensure the match doesn't span a newline (multiline
        # expressions often have explicit parens we don't track).
        if "\n" in stripped[m.start():m.end()]:
            continue
        # Reject matches where a parenthesis appears between the operators,
        # since `?? (b || c)` is legal even on one line.
        snippet = stripped[m.start():m.end()]
        if "(" in snippet or ")" in snippet:
            continue
        out.append(Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=str(root),
            file=rel,
            line=_line_of(text, m.start()),
            detail=(
                "JavaScript forbids un-parenthesised mixing of `??` with "
                "`||` or `&&` — parse error at runtime"
            ),
            fix_hint=(
                "wrap one side in parens: `a ?? (b || c)` or `(a ?? b) || c`"
            ),
            source=SOURCE,
            timestamp=now,
        ))
    return out


_SCRIPT_BODY_RE = re.compile(
    r"<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script\s*>",
    re.IGNORECASE | re.DOTALL,
)


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    root = ctx.repo_root

    # .js/.mjs/.cjs/.ts scanned as plain bodies.
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
        if "??" not in text:
            continue
        rel = path.relative_to(root).as_posix()
        verdicts.extend(_scan(text, rel, root, now))

    # .html: scan inline <script>...</script> only.
    for path in iter_repo_files(root, ("*.html", "*.htm"), JS_EXCLUDE_DIRS, population=POPULATION):
        if has_skip_marker(path):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "??" not in text:
            continue
        rel = path.relative_to(root).as_posix()
        for m in _SCRIPT_BODY_RE.finditer(text):
            body = m.group(1)
            body_start = m.start(1)
            for v in _scan(body, rel, root, now):
                # Shift line numbers from body-local to file-local.
                v_dict = {
                    "rule_id": v.rule_id, "severity": v.severity, "repo": v.repo,
                    "file": v.file, "line": v.line + _line_of(text, body_start) - 1,
                    "detail": v.detail, "fix_hint": v.fix_hint, "source": v.source,
                    "timestamp": v.timestamp,
                }
                verdicts.append(Verdict(**v_dict))
    return verdicts
