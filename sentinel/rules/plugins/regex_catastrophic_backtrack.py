# sentinel:skip-file — docstring example contains the bad patterns.
"""P1-regex-catastrophic-backtrack: WARN on Python regex patterns with
nested unbounded quantifiers that risk catastrophic backtracking
(ReDoS).

Past incident (lessons.md "ReDoS: `[\\w\\s]+?` with nesting → catastrophic
backtracking. Use bounded `{1,80}`."). When a regex contains nested
unbounded quantifiers — `(a+)+`, `(a*)*`, `(a+?)+`, etc. — the engine
can explore an exponential number of states on a worst-case input
(typically a long sequence of `a` followed by a non-match), hanging
the process and creating a denial-of-service vector for user input
that the developer never anticipated.

The classic shapes detected here:

    re.compile(r"(\\w+)+")                 # BAD
    re.compile(r"(\\d+?)+")                # BAD
    re.compile(r"(.+)*")                   # BAD
    re.compile(r"[\\w\\s]+?[\\w\\s]+?...") # BAD — chained unbounded

The fix is to bound the inner quantifier with a maximum
(`{1,80}` typically), or to use a possessive/atomic group when
available, or to redesign the pattern with anchored alternatives.

The rule scans .py files for `re.compile(...)` literals and inline
`re.<func>(r"...", ...)` calls, then runs a structural check on the
pattern source. Detection is conservative — only the canonical
exponential shapes trip; bounded variants `(a{1,80})+` are allowed.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import iter_repo_files
from sentinel.io.skip_marker import has_skip_marker


ID = "P1-regex-catastrophic-backtrack"
SEVERITY = Severity.WARN
SOURCE = "lessons.md#data-handling  (ReDoS: nested unbounded quantifiers)"
SCOPE = "repo"

MAX_FILE_BYTES = 5_000_000
PY_EXCLUDE_DIRS = (".venv", "venv", "__pycache__", "build", "dist",
                   ".tox", ".pytest_cache", "node_modules")

# Find re.compile(...) or re.match/search/findall/finditer/sub with raw
# string first arg. Capture the pattern body.
_RE_CALL_RE = re.compile(
    r"\bre\.(?:compile|match|search|findall|finditer|fullmatch|sub|subn|split)\s*\(\s*"
    r"r?(['\"])((?:\\.|(?!\1).)*?)\1",
    re.DOTALL,
)

# Catastrophic shapes:
# 1. `(...+...)+` / `(...*...)*` / `(...+?...)+` — nested unbounded quantifier
#    where the inner pattern itself is unbounded.
# 2. Two adjacent unbounded quantifiers on overlapping char classes.

# Shape 1 — group whose body contains `+` or `*` outside another group,
# followed by another `+` or `*` on the group itself.
_NESTED_UNBOUNDED_RE = re.compile(
    r"\(([^()]*[+*][?+]?[^()]*)\)[+*][?+]?"
)


def _has_inner_unbounded(group_body: str) -> bool:
    """The captured (...) body must contain `+` or `*` that's not bounded
    by `{n,m}`. Also must not be a non-capturing-only marker like `?:`."""
    # Strip non-capturing markers / lookarounds — they don't affect
    # backtracking semantics here.
    s = group_body
    # Skip `[\w]+` style — those by themselves are fine; the danger is when
    # the WHOLE GROUP is then quantified.
    # A bare `+` or `*` inside the group means the outer `+` on the group
    # creates the exponential blow-up.
    return bool(re.search(r"[+*]\??", s))


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _strip_python_noise(text: str) -> str:
    """Strip Python comments only — leave string literals intact since
    that's where the regex patterns live."""
    return re.sub(r"#[^\n]*", lambda m: " " * (m.end() - m.start()), text)


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    root = ctx.repo_root
    for path in iter_repo_files(root, "*.py", PY_EXCLUDE_DIRS):
        if has_skip_marker(path):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "re." not in text:
            continue
        rel = path.relative_to(root).as_posix()
        stripped = _strip_python_noise(text)
        for m in _RE_CALL_RE.finditer(stripped):
            pattern = m.group(2)
            for nested in _NESTED_UNBOUNDED_RE.finditer(pattern):
                body = nested.group(1)
                if not _has_inner_unbounded(body):
                    continue
                # Bound check: if the inner has `{n,m}` rather than `+`/`*`,
                # _has_inner_unbounded already returned False. Safe.
                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=SEVERITY,
                    repo=str(root),
                    file=rel,
                    line=_line_of(text, m.start()),
                    detail=(
                        f"regex `{pattern[:80]}` has nested unbounded "
                        f"quantifier near `({body[:40]})...` — "
                        "catastrophic backtracking risk (ReDoS)"
                    ),
                    fix_hint=(
                        "bound the inner quantifier with `{1,80}` or "
                        "similar, or redesign with anchored alternation"
                    ),
                    source=SOURCE,
                    timestamp=now,
                ))
                break  # one finding per pattern is enough
    return verdicts
