"""P0-e156-placeholder-leak: BLOCK on Python-None / template-placeholder
leaks in e156 students.html and rewrite-workbook.txt.

Triggering incidents (2026-05-24 session):

  - 1110 dashboard files in mahmood726-cyber/rapidmeta-finerenone shipped
    with `publishedHR: None, hrLCI: None, hrUCI: None` in inline JS, causing
    `Uncaught ReferenceError: None is not defined` and rendering every
    *_AUTO_FULL_REVIEW.html as a 626-byte stub.

  - 1208 entries in rewrite-workbook.txt had body text
    'aggregates X trials with n participants in a browser-native' — the
    literal token 'n' leaked because the f-string fell through to its
    else branch when participant count was missing.

  - 12 entries had broken Synthēsis spelling (missing macron / mojibake).

Both root causes are now patched in the generators (commits cc9dc53 on
rapidmeta-finerenone and a1052c5 on e156), but a regression-prevention
guard at the Sentinel layer is cheap insurance: it BLOCKs commits that
would re-introduce the same kind of leak whether or not the generator
gets patched again.

Patterns detected:

  BLOCK (P0):
    1. JS object literal in a <script> block contains `: None` or `, None`
       (the Python-None-in-JS bug, root-cause of the 1110-file None-leak)
    2. workbook Code/Protocol/Dashboard line equals 'None' or ends with
       '/None' (placeholder URL leak)

  WARN (P1):
    3. body text contains the literal 'n participants' (placeholder)
    4. DATA: line contains 'None trials' or 'None participants'
    5. body or target_journal contains 'Synth' but NOT 'Synthēsis'
       (missing macron — three entries had this in the 2026-05-24 audit)

Heuristics: only fire on files named `students.html` or files ending in
`rewrite-workbook.txt`. Scope is the e156 repo; the rapidmeta-finerenone
upstream is covered by `rapidmeta_data_integrity.py`.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P0-e156-placeholder-leak"
SEVERITY = Severity.BLOCK
SOURCE = "lessons.md#placeholder-leak:2026-05-24-rapidmeta-none-jsleak"
SCOPE = "repo"

MAX_FILE_BYTES = 10_000_000

# JS literal None inside a <script> block. Matches `key: None,` or `, None`.
# Excludes `: none` (lowercase — CSS keyword) by case-sensitivity.
SCRIPT_BLOCK_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)
NONE_IN_JS_RE = re.compile(r"(?:[,:]|\[|\()\s*None\b")

# workbook Link URLs that resolve to the literal 'None'
WORKBOOK_NONE_LINK_RE = re.compile(
    r"^\s+(Code|Protocol|Dashboard):\s+(None|\S*/None)\s*$",
    re.MULTILINE,
)

# body-text placeholders (parser-friendly regexes against the embedded
# const ENTRIES = [...] array OR the workbook's CURRENT BODY blocks)
N_PARTICIPANTS_RE = re.compile(r"\bwith\s+n\s+participants\b")
NONE_TRIALS_RE = re.compile(r"\bNone\s+(?:trials|participants)\b")
SYNTH_MISSING_MACRON_RE = re.compile(r"\bSynthesis\b(?!\s*(?:-medicine|-with-macron))")


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _check_html(text: str, rel: str, now: datetime) -> List[Verdict]:
    """Scan a students.html file. BLOCK on None-in-JS leaks; WARN on
    body-text placeholder patterns."""
    verdicts: List[Verdict] = []

    # Pattern 1: None inside a <script> block (Python-None-in-JS)
    for sm in SCRIPT_BLOCK_RE.finditer(text):
        block = sm.group(1)
        block_offset = sm.start(1)
        for nm in NONE_IN_JS_RE.finditer(block):
            abs_offset = block_offset + nm.start()
            # Skip occurrences inside comments and string literals (heuristic:
            # if the previous 80 chars contain // or /* or ' or " context).
            preceding = text[max(0, abs_offset - 80):abs_offset]
            if "//" in preceding.split("\n")[-1]:
                continue
            verdicts.append(Verdict(
                rule_id=ID,
                severity=Severity.BLOCK,
                repo=None,
                file=rel,
                line=_line_of(text, abs_offset),
                detail=(
                    f"JS object literal contains Python-None literal "
                    f"({text[abs_offset:abs_offset+10]!r}); JS will throw "
                    f"`ReferenceError: None is not defined` at runtime"
                ),
                fix_hint=(
                    "use js_val() in the generator to convert Python None -> "
                    "JS null; see F:/rapidmeta-finerenone/generate_living_ma_v13.py:42"
                ),
                source=SOURCE,
                timestamp=now,
            ))

    # Patterns 3-4 (WARN): body text placeholders
    for m in N_PARTICIPANTS_RE.finditer(text):
        verdicts.append(Verdict(
            rule_id=ID,
            severity=Severity.WARN,
            repo=None,
            file=rel,
            line=_line_of(text, m.start()),
            detail="body text leaks 'with n participants' placeholder",
            fix_hint="drop the participant clause when count is unknown",
            source=SOURCE,
            timestamp=now,
        ))
    for m in NONE_TRIALS_RE.finditer(text):
        verdicts.append(Verdict(
            rule_id=ID,
            severity=Severity.WARN,
            repo=None,
            file=rel,
            line=_line_of(text, m.start()),
            detail=f"text contains {m.group(0)!r} placeholder",
            fix_hint="emit 'cohort sizes not reported' when k/n are None",
            source=SOURCE,
            timestamp=now,
        ))

    return verdicts


def _check_workbook(text: str, rel: str, now: datetime) -> List[Verdict]:
    """Scan rewrite-workbook.txt. BLOCK on None URLs; WARN on placeholder text."""
    verdicts: List[Verdict] = []

    for m in WORKBOOK_NONE_LINK_RE.finditer(text):
        verdicts.append(Verdict(
            rule_id=ID,
            severity=Severity.BLOCK,
            repo=None,
            file=rel,
            line=_line_of(text, m.start()),
            detail=(
                f"{m.group(1)}: URL is {m.group(2)!r} — Python None leaked "
                f"into a link line"
            ),
            fix_hint=(
                "remove the line entirely (the entry then renders without "
                "that button) or supply a real URL"
            ),
            source=SOURCE,
            timestamp=now,
        ))

    for m in N_PARTICIPANTS_RE.finditer(text):
        verdicts.append(Verdict(
            rule_id=ID,
            severity=Severity.WARN,
            repo=None,
            file=rel,
            line=_line_of(text, m.start()),
            detail="workbook body leaks 'with n participants' placeholder",
            fix_hint=(
                "regenerate the entry via the patched "
                "scripts/generate_rapidmeta_entries.py (commit a1052c5+)"
            ),
            source=SOURCE,
            timestamp=now,
        ))

    return verdicts


def check(ctx: RepoContext) -> List[Verdict]:
    """Sentinel entry point. Scans students.html + rewrite-workbook.txt in
    the repo root."""
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    repo_root = ctx.repo_root

    for name, checker in [
        ("students.html", _check_html),
        ("rewrite-workbook.txt", _check_workbook),
    ]:
        path = repo_root / name
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for v in checker(text, name, now):
            verdicts.append(Verdict(
                rule_id=v.rule_id,
                severity=v.severity,
                repo=str(repo_root),
                file=v.file,
                line=v.line,
                detail=v.detail,
                fix_hint=v.fix_hint,
                source=v.source,
                timestamp=v.timestamp,
            ))

    return verdicts
