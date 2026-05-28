"""P1-realdata-provenance: WARN when a dashboard's realData carries source
provenance on SOME trials but not others.

E156 Assurance Standard "Data extraction errors" risk class, check #4
(data->provenance): every extracted number should trace to a source
(paper/page/table). The standard's ideal is row-level provenance on every
trial.

FP discipline (2026-05-28 portfolio FP audit): the vast majority of existing
rapidmeta dashboards carry NO source field at all, so demanding one everywhere
would flood the portfolio with thousands of WARNs. Instead this rule fires only
on INCONSISTENCY — when the provenance convention is demonstrably in use (>=1
trial has a source/citation/doi/pmid/url field) but other trials in the same
realData block lack it. That is a genuine internal-consistency defect (the
author added provenance to some rows and forgot others) and matches the
standard's "the capsule must agree with itself" principle, without penalising
capsules that haven't adopted row-level provenance yet.

WARN only; honors sentinel:skip-file. Targets *_REVIEW.html + students.html.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.rules.plugins.denominator_logic import (
    _iter_html_files,
    _iter_realdata_entries,
    _line_of,
)


ID = "P1-realdata-provenance"
SEVERITY = Severity.WARN
SOURCE = "F:\\e156\\docs\\assurance-standard.md#2-data-checking"
SCOPE = "repo"

MAX_FILE_BYTES = 10_000_000
SKIP_MARKER = "sentinel:skip-file"

PROVENANCE_RE = re.compile(
    r"\b(source|citation|reference|ref|doi|pmid|pmcid|url|sourceUrl|provenance)\s*:\s*"
    r"('[^']*'|\"[^\"]*\"|\S+)",
    re.IGNORECASE,
)
_EMPTY_VALUES = frozenset(("", "null", "none", "tbd", "n/a", "-", "_"))


def _has_provenance(entry: str) -> bool:
    for m in PROVENANCE_RE.finditer(entry):
        val = m.group(2).strip().strip("'\"").strip()
        if val.lower() not in _EMPTY_VALUES:
            return True
    return False


def _check_one_file(text: str, rel: str, now: datetime) -> List[Verdict]:
    entries = list(_iter_realdata_entries(text))
    if len(entries) < 2:
        return []

    flagged = [(nct, ofs, _has_provenance(entry)) for nct, entry, ofs in entries]
    have = [f for f in flagged if f[2]]
    lack = [f for f in flagged if not f[2]]
    # Only fire on inconsistency: convention in use (some have it) but incomplete.
    if not have or not lack:
        return []

    verdicts: List[Verdict] = []
    for nct, ofs, _ in lack:
        verdicts.append(Verdict(
            rule_id=ID,
            severity=Severity.WARN,
            repo=None,
            file=rel,
            line=_line_of(text, ofs),
            detail=(
                f"trial {nct} has no source/provenance field, but "
                f"{len(have)} of {len(flagged)} trials in this realData block do "
                f"— every extracted row must trace to a source"
            ),
            fix_hint=(
                "add a source field (e.g. source/citation/doi/pmid) to this "
                "trial pointing to the paper/table the numbers came from, so the "
                "provenance is complete across all trials"
            ),
            source=SOURCE,
            timestamp=now,
        ))
    return verdicts


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    root = ctx.repo_root
    verdicts: List[Verdict] = []
    for path in _iter_html_files(root):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if SKIP_MARKER in text:
            continue
        rel = path.relative_to(root).as_posix()
        for v in _check_one_file(text, rel, now):
            verdicts.append(Verdict(
                rule_id=v.rule_id,
                severity=v.severity,
                repo=str(root),
                file=v.file,
                line=v.line,
                detail=v.detail,
                fix_hint=v.fix_hint,
                source=v.source,
                timestamp=v.timestamp,
            ))
    return verdicts
