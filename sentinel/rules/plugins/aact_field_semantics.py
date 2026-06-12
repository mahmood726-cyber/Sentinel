"""P1-aact-field-semantics: WARN when code filters on an AACT field whose name
misleads about its meaning, so the author confirms the semantics before trusting it.

Incident: aact-cockpit's FDAAA-debt audit filtered `is_us_export = 't'` believing
it meant "US-located / US-nexus trial". In AACT that flag means a product EXPORTED
from the US for study ABROAD (~3% of trials, not the ~40% a US-site filter would
match). The eligibility reconciled perfectly and shipped wrong. A multi-persona
review caught it; this rule catches the class of error at pre-push, portfolio-wide.

Narrow by design (low FP, see MEMORY.md Sentinel FP audit):
  - WARN, not BLOCK (these are confirm-the-meaning prompts, not certain bugs).
  - Fires ONLY when a listed field is used as a FILTER: a comparison operator
    (== != <>), or a single '=' to a SHORT quoted literal (the SQL `= 't'` shape).
    A single '=' to an unquoted/long value (Python assignment / kwarg / fixture
    like `why_stopped=None`) and bare prose mentions do NOT fire.
  - Skips node_modules / minified bundles / vendored copies and `sentinel:skip-file`.

Known-legitimate FP shape: a field-semantics registry that documents these fields
on purpose (e.g. aact-cockpit `audits.py::FLAG_META`) — mark that file skip-file.

Override: add `sentinel:skip-file` (or `<!-- sentinel:skip-file -->`) to the file.
"""
from __future__ import annotations

import re
from pathlib import Path
from datetime import datetime, timezone
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import iter_tree_or_filter

ID = "P1-aact-field-semantics"
SEVERITY = Severity.WARN
SOURCE = "C:\\Users\\mahmo\\.claude\\projects\\C--Users-mahmo\\memory\\aactcockpit_project.md"
SCOPE = "repo"

EXCLUDE_DIRS = frozenset((
    "node_modules", "__pycache__", ".git", ".pytest_cache", ".venv", "venv",
    "build", "dist", "_vendor", "vendor", "third_party",
))
EXTS = frozenset((".py", ".sql", ".js", ".mjs", ".ts"))

# AACT fields whose name misleads about meaning. Value = the TRUE meaning to show.
MISLEADING_FIELDS = {
    "is_us_export": ("a product EXPORTED from the US for study abroad — NOT whether the trial "
                     "has US sites or US nexus (~3% of trials)"),
    "is_fda_regulated_drug": ("a self-declared FDA-regulated drug/biologic — not a guarantee of "
                              "FDAAA applicability or US conduct"),
    "is_fda_regulated_device": ("a self-declared FDA-regulated device — not a guarantee of FDAAA "
                                "applicability or US conduct"),
    "last_known_status": ("only populated when overall_status is UNKNOWN/stale — it is NOT the "
                          "current status of every trial"),
    "why_stopped": ("free text present only for terminated/withdrawn/suspended studies — its "
                    "absence does not mean a trial completed"),
    "enrollment_type": ("'Anticipated' vs 'Actual' — filtering enrollment without checking this "
                        "mixes planned and realised counts"),
}

# A FILTER is: a comparison operator (== != <>), OR a single '=' to a SHORT quoted
# literal (the SQL boolean/code-filter shape: `= 't'`, `= 'Randomized'`). A single
# '=' to an unquoted or long value is a Python assignment / keyword argument / test
# fixture, NOT a field filter — excluding it kills the `why_stopped=None` and
# `why_stopped="long sentence"` false positives found in the portfolio FP audit.
# Word-operators (IN/LIKE/IS) are omitted to avoid prose FPs.
_FILTER = r"""(?:==|!=|<>|=\s*['"][^'"]{1,12}['"])"""
# lookbehind rejects only a preceding word char (so `xis_us_export` is not matched)
# but ALLOWS a dot, so `s.is_us_export` (SQL alias) and `row.field` (attribute) match —
# those are exactly how the field gets filtered.
_PATTERNS = {
    f: re.compile(rf"(?<!\w){re.escape(f)}\s*{_FILTER}", re.IGNORECASE)
    for f in MISLEADING_FIELDS
}


def _iter_files(root: Path):
    for p in iter_tree_or_filter(root):  # changed-file scope under --diff
        if not p.is_file():
            continue
        if p.suffix.lower() not in EXTS:
            continue
        if any(part in EXCLUDE_DIRS for part in p.parts):
            continue
        if p.name.endswith(".min.js") or p.name.endswith(".bundle.js"):
            continue
        yield p


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    out: List[Verdict] = []
    root = ctx.repo_root
    for p in _iter_files(root):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "sentinel:skip-file" in text:
            continue
        rel = p.relative_to(root).as_posix()
        seen: set[tuple[str, int]] = set()
        for field, rx in _PATTERNS.items():
            for m in rx.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                key = (field, line)
                if key in seen:
                    continue
                seen.add(key)
                out.append(Verdict(
                    rule_id=ID, severity=Severity.WARN, repo=str(root), file=rel, line=line,
                    detail=(f"filters on AACT field '{field}', which means {MISLEADING_FIELDS[field]} "
                            f"— confirm this is the intended semantics"),
                    fix_hint=("verify the field's AACT data-dictionary meaning; if intended, document it "
                              "(e.g. a FLAG_META-style note) and add sentinel:skip-file"),
                    source=SOURCE, timestamp=now))
    return out
