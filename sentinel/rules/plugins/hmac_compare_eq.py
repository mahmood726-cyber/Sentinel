# sentinel:skip-file — docstring example contains the bad pattern.
"""P0-hmac-compare-eq: BLOCK on `==` / `!=` comparison of HMAC / digest /
signature values where `hmac.compare_digest` should be used.

Past incident (lessons.md "Constant-time comparison: Always
`hmac.compare_digest`, never `==`"). The `==` operator on strings/bytes
short-circuits on the first differing byte, which leaks the byte
position to a timing attacker. The fix is the constant-time
`hmac.compare_digest(a, b)`.

The rule scans .py files for `==` or `!=` comparisons where at least
one operand has an HMAC/MAC/digest/signature identifier. False
positives are kept low by requiring the identifier to literally
contain one of the canonical tokens.

    if hmac_value == expected:     # BAD — timing leak
    if signature != trusted_sig:   # BAD — timing leak
    if compare_digest(a, b):       # OK

Severity is BLOCK because the failure mode is silent — the wrong
comparison passes all functional tests; the vulnerability only shows
in production under adversarial conditions.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import iter_repo_files
from sentinel.io.skip_marker import has_skip_marker, line_is_suppressed


ID = "P0-hmac-compare-eq"
SEVERITY = Severity.BLOCK
SOURCE = ("lessons.md#cryptography--signing-learned-2026-04-14  "
          "(Constant-time comparison: always hmac.compare_digest, never ==)")
SCOPE = "repo"

MAX_FILE_BYTES = 5_000_000
PY_EXCLUDE_DIRS = (".venv", "venv", "__pycache__", "build", "dist",
                   ".tox", ".pytest_cache", "node_modules")

# Identifier-sensitivity check: substring match on full crypto tokens.
# V1 (2026-05-25) had suffix forms `_sig` / `_tag` / `_mac` in the list,
# but those collided with `same_sig`/`ref_sig` (statistical significance)
# in MetaReproducer (2026-05-27 portfolio scan). Substring match on the
# FULL WORDS only is unambiguous: `signature` is not a substring of
# `significance` (the two share only the `sign` prefix), `mac_value` is
# not a substring of `macroaverage`, and `auth_tag` is not a substring
# of `tags`.
#
# Real crypto identifiers like `hmac_value`, `bundle.signature`,
# `signature_method` all contain a full token as substring → fire.
SENSITIVE_TOKENS = (
    "hmac", "signature", "digest", "mac_value", "auth_tag", "auth_code",
)

# Identifier on one side: standard Python identifier, possibly dotted
# (e.g. `bundle.signature` or `result.hmac`).
_IDENT = r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"

# `LHS == RHS` / `LHS != RHS` — broad form, then filter by sensitivity.
_EQ_RE = re.compile(
    rf"({_IDENT})\s*(==|!=)\s*({_IDENT})"
)

# Strip Python comments + string literals before regex matching so
# patterns inside strings/docstrings don't trip.
_LINE_COMMENT_RE = re.compile(r"#[^\n]*")
_STRING_RE = re.compile(
    r"'''(?:\\.|.)*?'''|\"\"\"(?:\\.|.)*?\"\"\""
    r"|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"",
    re.DOTALL,
)


def _strip_noise(text: str) -> str:
    def _ws(m):
        return " " * (m.end() - m.start())
    text = _STRING_RE.sub(_ws, text)
    text = _LINE_COMMENT_RE.sub(_ws, text)
    return text


def _is_sensitive(ident: str) -> bool:
    """True if `ident` (a Python identifier, possibly dotted) contains
    a crypto-sensitive full token as substring. The full-token-only
    list distinguishes `signature` from `significance` cleanly."""
    low = ident.lower()
    return any(tok in low for tok in SENSITIVE_TOKENS)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


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
        # Cheap pre-filter: only parse files mentioning a sensitive word.
        # Using broad substring match here is fine — _is_sensitive applies
        # the strict word/suffix check per-match.
        low_text = text.lower()
        if not any(t in low_text for t in
                   ("hmac", "signature", "digest", "mac_value",
                    "auth_tag", "auth_code")):
            continue
        stripped = _strip_noise(text)
        lines = text.splitlines()
        rel = path.relative_to(root).as_posix()
        seen_offsets: set[int] = set()
        for m in _EQ_RE.finditer(stripped):
            lhs, op, rhs = m.group(1), m.group(2), m.group(3)
            if not (_is_sensitive(lhs) or _is_sensitive(rhs)):
                continue
            if m.start() in seen_offsets:
                continue
            seen_offsets.add(m.start())
            line_no = _line_of(text, m.start())
            cur = lines[line_no - 1] if line_no - 1 < len(lines) else ""
            prv = lines[line_no - 2] if line_no - 2 >= 0 else ""
            if line_is_suppressed(cur, prv, ID):
                continue
            verdicts.append(Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(root),
                file=rel,
                line=line_no,
                detail=(
                    f"`{lhs} {op} {rhs}` uses non-constant-time comparison "
                    "on a crypto-sensitive value — timing-attack leak"
                ),
                fix_hint=(
                    "use `hmac.compare_digest(a, b)` for byte-equal "
                    "comparisons of MAC / signature / digest values"
                ),
                source=SOURCE,
                timestamp=now,
            ))
    return verdicts
