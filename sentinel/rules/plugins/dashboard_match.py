"""P1-dashboard-match: WARN when a rendered review's workbook-level pooled
HR/OR claim is incompatible with the per-trial values inside its own
realData block.

E156 Assurance Standard "dashboard_match" check (Silver-tier enabler).

The dashboards (rapidmeta_*_REVIEW.html) compute the pooled estimate live
in JavaScript at render time, so the static HTML carries only "--"
placeholders for #res-or / #res-ci / #res-i2. A direct workbook-vs-rendered
value comparison would require a headless browser — deferred to Phase 3.

This rule ships the **minimum-viable consistency check**: the rendered
review IS the workbook entry's source of truth, so each review's own
realData block carries per-trial HR / CI values. If the prose claim
(extracted from the body of the same file) names a pooled HR that's
outside the union of per-trial bounds (with a generous tolerance), the
review is internally inconsistent — same family as the fabrication-pack
self-contradiction rule but at the per-file pooled level.

Fires only when:
  1. The file has a realData block AND ≥2 trials with parseable
     publishedHR.
  2. The file has at least one body-level "Pooled OR/HR <num> (95% CI
     <lo>-<hi>)" claim in non-script prose.
  3. The body's pooled HR is outside the per-trial min/max range by
     more than 0.2 absolute (a pooled estimate can legitimately fall
     slightly outside individual trial estimates under random-effects,
     but never by a huge margin).

Tolerance is conservative — better to under-report than to flood
operators with noise on legitimate large heterogeneity.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import path_allowed
from sentinel.rules.plugins.denominator_logic import (
    _iter_realdata_entries,
    _line_of,
    NUM_FIELD_RE,
    _parse_value,
)


ID = "P1-dashboard-match"
SEVERITY = Severity.WARN
SOURCE = ("F:\\e156\\docs\\assurance-standard.md#paper-dashboard-match  "
          "(Phase 2b minimum-viable; Phase 3 headless-browser version planned)")
SCOPE = "repo"

MAX_FILE_BYTES = 10_000_000
TOLERANCE_ABS = 0.2   # pooled HR may legitimately drift this far from per-trial range under RE pooling

POOLED_BODY_RE = re.compile(
    r"\b(?:pooled\s+)?(OR|HR|RR|IRR)\s*[:=]?\s*(\d+\.\d+)\s*"
    r"[\(\[,]?\s*(?:95\s*%?\s*CI\s*:?\s*)?"
    r"(\d+\.\d+)\s*[-–to]+\s*(\d+\.\d+)",
    re.IGNORECASE,
)
SCRIPT_BLOCK_RE = re.compile(r"<script\b[^>]*>.*?</script>", re.DOTALL | re.IGNORECASE)


def _iter_target_files(root: Path):
    for p in root.glob("*_REVIEW.html"):
        if not path_allowed(root, p):
            continue  # honor `scan --diff` changed-file scope
        yield p


def _strip_scripts(text: str) -> str:
    """Remove <script>...</script> blocks so body extraction doesn't see
    JS data literals as 'pooled' claims."""
    return SCRIPT_BLOCK_RE.sub("", text)


def _per_trial_hrs(text: str) -> list[tuple[str, float, float, float]]:
    """Return [(nct, hr, lci, uci), ...] for trials that have all three."""
    out = []
    for nct, entry, _ofs in _iter_realdata_entries(text):
        fields = {}
        for fm in NUM_FIELD_RE.finditer(entry):
            fields[fm.group(1)] = _parse_value(fm.group(2))
        hr = fields.get("publishedHR")
        lci = fields.get("hrLCI")
        uci = fields.get("hrUCI")
        if all(isinstance(v, (int, float)) for v in (hr, lci, uci)):
            out.append((nct, float(hr), float(lci), float(uci)))
    return out


def _check_one_file(text: str, rel: str, now: datetime) -> List[Verdict]:
    verdicts: List[Verdict] = []
    trials = _per_trial_hrs(text)
    if len(trials) < 2:
        return verdicts

    body = _strip_scripts(text)
    body_match = POOLED_BODY_RE.search(body)
    if not body_match:
        return verdicts

    try:
        body_hr = float(body_match.group(2))
    except ValueError:
        return verdicts

    hrs = [t[1] for t in trials]
    lo, hi = min(hrs), max(hrs)

    if body_hr < lo - TOLERANCE_ABS or body_hr > hi + TOLERANCE_ABS:
        # Find original-text offset for line reporting
        orig_offset = text.find(body_match.group(0))
        line = _line_of(text, orig_offset if orig_offset >= 0 else 0)
        verdicts.append(Verdict(
            rule_id=ID,
            severity=Severity.WARN,
            repo=None,
            file=rel,
            line=line,
            detail=(
                f"body claims pooled {body_match.group(1)} {body_hr} but "
                f"per-trial HRs in realData range from {lo:.2f} to {hi:.2f} "
                f"({len(trials)} trials); pooled estimate is implausibly "
                f"outside the per-trial range by >{TOLERANCE_ABS}"
            ),
            fix_hint=(
                "re-verify the pooled estimate against the dashboard's "
                "computed value (open the live page); if the body claim is "
                "stale, regenerate it from the current pooling"
            ),
            source=SOURCE,
            timestamp=now,
        ))
    return verdicts


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    root = ctx.repo_root
    for path in _iter_target_files(root):
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
