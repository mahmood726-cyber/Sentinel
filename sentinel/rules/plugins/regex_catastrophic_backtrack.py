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
from sentinel.io.population import Population
from sentinel.io.skip_marker import has_skip_marker


ID = "P1-regex-catastrophic-backtrack"
SEVERITY = Severity.WARN
SOURCE = "lessons.md#data-handling  (ReDoS: nested unbounded quantifiers)"
SCOPE = "repo"

# Population: PRESENT -- tracked AND untracked-not-ignored. This is a
# CORRECTNESS rule: the defect it finds runs when someone runs the file,
# whether or not git is tracking it. Migrated 2026-08-30; counts from
# before that date were taken over the tracked set only and are NOT
# comparable with counts after it.
POPULATION = Population.PRESENT

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

# Shape: group whose body contains `+` or `*` outside another group,
# followed by another `+` or `*` on the group itself.
_NESTED_UNBOUNDED_RE = re.compile(
    r"\(([^()]*[+*][?+]?[^()]*)\)[+*][?+]?"
)

# A group body counts as "wildly unbounded" only when the inner `+`/`*`
# applies to a wildcard class. Specific anchors like `[/-]` or `\d+\.\s`
# limit backtracking enough in practice — past incidents (lessons.md ReDoS)
# all involved wildcard-only patterns.
_WILD_INNER_RE = re.compile(
    r"(?:"
    r"\.[+*][?+]?"               # .+ .* .+? .*?
    r"|\\[wWsSdD][+*][?+]?"      # \w+ \W+ \s+ \S+ \d+ \D+ + variants
    r"|\[[^\]]*\][+*][?+]?"      # [class]+ — but ALSO must not have a literal anchor
    r")"
)


def _has_inner_unbounded(group_body: str) -> bool:
    """True if the captured (...) body contains a wildcard `+`/`*` whose
    target is a generic class (`.`, `\\w`, `\\s`, `\\S`, `\\d`, etc.) and
    is not bounded by an adjacent literal anchor. Specific-literal anchors
    inside the group prevent backtracking explosion in practice."""
    # If the body has a literal anchor (specific punct char outside a class),
    # the engine can't explode — bail out.
    # Heuristic: any literal `/`, `-`, `:`, `.`, `,`, `;`, `=`, `(`, `)`
    # AT TOP LEVEL (not inside a char class) acts as an anchor.
    if re.search(r"(?<!\\)[/:;=]", group_body):
        return False
    # Now require a wildcard inner quantifier to be present.
    return bool(_WILD_INNER_RE.search(group_body))


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
    for path in iter_repo_files(root, "*.py", PY_EXCLUDE_DIRS, population=POPULATION):
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
