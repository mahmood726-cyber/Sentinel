"""P1-fabrication-implausible-precision: WARN when a CI is impossibly narrow
given the trial's sample size.

E156 Assurance Standard fabrication-detection family (BadScientist-inspired,
arXiv 2510.18003). Tight CIs at small cohorts are typically copy-paste tells:
the bounds weren't really computed, they were inherited from a different
trial. A real 95% CI on a HR/OR from n<5000 will rarely be tighter than
0.05 absolute width; <0.01 is essentially impossible.

Heuristic:
  - WARN when (hrUCI - hrLCI) < 0.01 AND (tN + cN) < 5000
  - WARN when (hrUCI - hrLCI) < 0.05 AND (tN + cN) < 500
  - Skip if any of hrLCI/hrUCI/tN/cN is None (denominator_logic + Phase-1
    None-fix already cover that family)
  - Skip zero-width CIs (lci == uci) — denominator_logic blocks those
    separately as data-entry errors; don't double-fire.

Reuses _iter_realdata_entries + _parse_value from denominator_logic to
avoid reimplementing the realData JSON-ish parser.
"""
from __future__ import annotations

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


ID = "P1-fabrication-implausible-precision"
SEVERITY = Severity.WARN
SOURCE = ("F:\\e156\\docs\\assurance-standard.md#data-checking  "
          "(BadScientist family, arXiv 2510.18003)")
SCOPE = "repo"

MAX_FILE_BYTES = 10_000_000

# Realistic-precision floors. A 95% CI on an HR from a typical RCT:
#   N=200  => CI width ~0.4-0.8 (huge)
#   N=5000 => CI width ~0.05-0.15 (still loose)
#   N=50000 => CI width ~0.01-0.05 (possible at this size)
#   N=500000 => CI width <0.01 (only mega-meta-analyses or registry data)
TIGHT_THRESHOLD = 0.01     # absolute CI width below this → suspicious
TIGHT_N_CEILING = 5_000    # ... unless cohort is huge

LOOSE_THRESHOLD = 0.05     # second-tier: width <0.05 also suspicious...
LOOSE_N_CEILING = 500      # ... at very small cohorts (n<500)


def _iter_html_files(root: Path):
    for p in root.glob("*_REVIEW.html"):
        if not path_allowed(root, p):
            continue  # honor `scan --diff` changed-file scope
        yield p
    sp = root / "students.html"
    if sp.is_file():
        yield sp


def _check_one_file(text: str, rel: str, now: datetime) -> List[Verdict]:
    verdicts: List[Verdict] = []
    for nct, entry, abs_offset in _iter_realdata_entries(text):
        fields = {}
        for fm in NUM_FIELD_RE.finditer(entry):
            fields[fm.group(1)] = _parse_value(fm.group(2))
        lci = fields.get("hrLCI")
        uci = fields.get("hrUCI")
        tN = fields.get("tN")
        cN = fields.get("cN")
        if not all(isinstance(v, (int, float)) for v in (lci, uci, tN, cN)):
            continue
        # denominator_logic already blocks lci == uci; don't double-fire
        width = uci - lci
        if width <= 0:
            continue
        n_total = tN + cN
        if width < TIGHT_THRESHOLD and n_total < TIGHT_N_CEILING:
            verdicts.append(Verdict(
                rule_id=ID,
                severity=Severity.WARN,
                repo=None,
                file=rel,
                line=_line_of(text, abs_offset),
                detail=(
                    f"trial {nct}: CI width {width:.4f} at n={n_total} is "
                    f"implausibly tight — real 95% CIs at this cohort size "
                    f"are typically >0.05 wide. Possible copy-paste from a "
                    f"different trial."
                ),
                fix_hint=(
                    "re-verify hrLCI/hrUCI against the source paper; if the "
                    "values are correct, document the trial design that "
                    "yielded such tight precision"
                ),
                source=SOURCE,
                timestamp=now,
            ))
        elif width < LOOSE_THRESHOLD and n_total < LOOSE_N_CEILING:
            verdicts.append(Verdict(
                rule_id=ID,
                severity=Severity.WARN,
                repo=None,
                file=rel,
                line=_line_of(text, abs_offset),
                detail=(
                    f"trial {nct}: CI width {width:.3f} at n={n_total} is "
                    f"suspiciously tight for a small cohort"
                ),
                fix_hint="re-verify the bounds against the source paper",
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
