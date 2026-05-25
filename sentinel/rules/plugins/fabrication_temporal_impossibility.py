"""P1-fabrication-temporal-impossibility: WARN when a trial's year field
creates a chronologically impossible scenario.

E156 Assurance Standard fabrication-detection family (BadScientist-inspired,
arXiv 2510.18003). Time-based contradictions are some of the easiest
fabrication tells to detect because dates are integers with hard
real-world constraints. Examples:

  - year > current_year      (no future trials)
  - year < 1975              (pre-CONSORT-era; possible but suspicious in modern MAs)
  - year + follow_up/12 > current_year + 1  (publication-window plausibility)

Heuristic: parse the year field from each realData trial entry, plus an
optional follow_up_months field if captured. Fire on any of the three
conditions above. Conservative — won't fire if year/follow_up are missing
or unparseable.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.rules.plugins.denominator_logic import (
    _iter_realdata_entries,
    _line_of,
    NUM_FIELD_RE,
    _parse_value,
)


ID = "P1-fabrication-temporal-impossibility"
SEVERITY = Severity.WARN
SOURCE = ("F:\\e156\\docs\\assurance-standard.md#data-checking  "
          "(BadScientist family, arXiv 2510.18003)")
SCOPE = "repo"

MAX_FILE_BYTES = 10_000_000

YEAR_FLOOR = 1975         # CONSORT-era pre-floor; before this is rare in modern MAs
CURRENT_YEAR = datetime.now(timezone.utc).year
YEAR_CEILING = CURRENT_YEAR  # no future trials
PUB_WINDOW_SLACK_YEARS = 1   # publication can lag completion by ~1 year

# Extended field capture — denominator_logic captures (tE, tN, cE, cN,
# publishedHR, hrLCI, hrUCI, phase) but not year or follow_up. We need a
# slightly wider pattern. Reuse the parser semantics.
EXTRA_FIELD_RE = re.compile(
    r"\b(year|follow_up_months|followUpMonths|follow_up_years)\s*:\s*"
    r"(null|None|'[^']*'|-?\d+\.?\d*)",
)


def _iter_html_files(root: Path):
    for p in root.glob("*_REVIEW.html"):
        yield p


def _check_one_file(text: str, rel: str, now: datetime) -> List[Verdict]:
    verdicts: List[Verdict] = []
    for nct, entry, abs_offset in _iter_realdata_entries(text):
        fields = {}
        for fm in NUM_FIELD_RE.finditer(entry):
            fields[fm.group(1)] = _parse_value(fm.group(2))
        for fm in EXTRA_FIELD_RE.finditer(entry):
            fields[fm.group(1)] = _parse_value(fm.group(2))

        year = fields.get("year")
        if not isinstance(year, (int, float)):
            continue
        year = int(year)
        line = _line_of(text, abs_offset)

        if year > YEAR_CEILING:
            verdicts.append(Verdict(
                rule_id=ID,
                severity=Severity.WARN,
                repo=None,
                file=rel,
                line=line,
                detail=(
                    f"trial {nct}: year={year} is in the future "
                    f"(current year is {CURRENT_YEAR})"
                ),
                fix_hint="verify the trial year against the source paper "
                         "(typo? completion vs registration year confusion?)",
                source=SOURCE,
                timestamp=now,
            ))
            continue

        if year < YEAR_FLOOR:
            verdicts.append(Verdict(
                rule_id=ID,
                severity=Severity.WARN,
                repo=None,
                file=rel,
                line=line,
                detail=(
                    f"trial {nct}: year={year} predates the CONSORT era "
                    f"({YEAR_FLOOR}) — possible but rare in modern MAs; "
                    f"verify against source"
                ),
                fix_hint="if the trial really is that old, document the "
                         "scope rationale; otherwise verify against the source",
                source=SOURCE,
                timestamp=now,
            ))
            continue

        # Follow-up plausibility
        fu_months = fields.get("follow_up_months") or fields.get("followUpMonths")
        if not isinstance(fu_months, (int, float)):
            fu_years = fields.get("follow_up_years")
            if isinstance(fu_years, (int, float)):
                fu_months = fu_years * 12
        if isinstance(fu_months, (int, float)) and fu_months > 0:
            end_year = year + (fu_months / 12.0)
            if end_year > CURRENT_YEAR + PUB_WINDOW_SLACK_YEARS:
                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=Severity.WARN,
                    repo=None,
                    file=rel,
                    line=line,
                    detail=(
                        f"trial {nct}: year={year} + follow_up "
                        f"{fu_months} months = {end_year:.1f}, but current "
                        f"year is {CURRENT_YEAR} — follow-up extends beyond "
                        f"plausible publication window"
                    ),
                    fix_hint=(
                        "verify either the year or the follow-up duration; "
                        "completed-vs-still-recruiting status?"
                    ),
                    source=SOURCE,
                    timestamp=now,
                ))
    return verdicts


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    root = ctx.repo_root
    for path in _iter_html_files(root):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
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
