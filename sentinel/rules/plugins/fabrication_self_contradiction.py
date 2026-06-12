"""P1-fabrication-self-contradiction: WARN when an entry's body claims
"no difference" / "non-significant" but quotes a CI whose bounds are
both on the same side of the null.

E156 Assurance Standard fabrication-detection family (BadScientist-inspired,
arXiv 2510.18003 and adjacent 2025-26 work). Self-contradiction is the
cheapest fabrication signal: the prose claims one thing, the numbers
demonstrate the opposite, but the author didn't notice because they
copy-pasted the conclusion from a different paper.

Example finding:
  "Across pooled trials there was no significant difference between
   intervention and control (OR 0.55, 95% CI 0.42-0.68)."
  -> The CI doesn't bracket 1.00, so the effect IS significant. Either
     the verbal claim or the number is wrong.

Heuristic:
  - Find a "no-difference" verbal claim (one of NO_DIFF_PATTERNS).
  - Within ±300 chars of that claim, find a ratio-measure CI
    (OR/HR/RR with 95% CI bounds).
  - WARN if BOTH bounds lie wholly above OR wholly below 1.00.
  - WARN if the verbal claim is followed by an absolute-difference CI
    that doesn't bracket 0.

Conservative — only fires when both signals are in the same sentence
range (300 chars). Avoids cross-paragraph false positives.

Files scanned: same as denominator_logic — *_REVIEW.html and students.html.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import path_allowed


ID = "P1-fabrication-self-contradiction"
SEVERITY = Severity.WARN
SOURCE = ("F:\\e156\\docs\\assurance-standard.md#claim-certainty-match  "
          "(BadScientist family, arXiv 2510.18003)")
SCOPE = "repo"

MAX_FILE_BYTES = 10_000_000

# Verbal "no difference" / null-result claims. \b word-boundaries.
NO_DIFF_RE = re.compile(
    r"\b(no\s+(?:significant\s+)?difference|null\s+result|not\s+significant|"
    r"non-?significant|comparable\s+(?:outcomes?|efficacy|risk|rates?)|"
    r"equivalent\s+(?:outcomes?|efficacy)|no\s+benefit)\b",
    re.IGNORECASE,
)

# Ratio-measure CI: "OR 0.55, 95% CI 0.42-0.68" / "HR 1.20 (0.95-1.51)" etc.
# Allow various separators between point and CI; require numeric CI bounds.
RATIO_CI_RE = re.compile(
    r"\b(OR|HR|RR|IRR|aHR|aOR)\b[\s:=]*"
    r"(\d+\.\d+)\s*[\(\[,]?\s*"
    r"(?:95\s*%?\s*CI\s*:?\s*)?"
    r"(\d+\.\d+)\s*[-–to]+\s*(\d+\.\d+)",
    re.IGNORECASE,
)

# Absolute-difference CI: "MD -2.3 (95% CI -3.1 to -1.5)"
ABS_CI_RE = re.compile(
    r"\b(MD|SMD|difference)\b[\s:=]*"
    r"(-?\d+\.\d+)\s*[\(\[,]?\s*"
    r"(?:95\s*%?\s*CI\s*:?\s*)?"
    r"(-?\d+\.\d+)\s*[-–to]+\s*(-?\d+\.\d+)",
    re.IGNORECASE,
)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _iter_target_files(root: Path):
    """Same target set as denominator_logic."""
    for p in root.glob("*_REVIEW.html"):
        if not path_allowed(root, p):
            continue  # honor `scan --diff` changed-file scope
        yield p
    sp = root / "students.html"
    if sp.is_file():
        yield sp
    wb = root / "rewrite-workbook.txt"
    if wb.is_file():
        yield wb


def _check_one_file(text: str, rel: str, now: datetime) -> List[Verdict]:
    verdicts: List[Verdict] = []
    for m in NO_DIFF_RE.finditer(text):
        # Look for a ratio or absolute CI within ±300 chars of the claim.
        window_start = max(0, m.start() - 300)
        window_end = min(len(text), m.end() + 300)
        window = text[window_start:window_end]

        for cim in RATIO_CI_RE.finditer(window):
            try:
                lo = float(cim.group(3))
                hi = float(cim.group(4))
            except ValueError:
                continue
            # Both bounds above 1.00 OR both below 1.00 → significant; verbal
            # claim of "no difference" contradicts it.
            if (lo > 1.0 and hi > 1.0) or (lo < 1.0 and hi < 1.0):
                if abs(lo - 1.0) < 0.005 or abs(hi - 1.0) < 0.005:
                    continue  # bound near 1.00 is borderline; skip
                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=Severity.WARN,
                    repo=None,
                    file=rel,
                    line=_line_of(text, m.start()),
                    detail=(
                        f"'{m.group(0)}' claim near {cim.group(1)} "
                        f"{cim.group(2)} ({lo}-{hi}) — CI doesn't bracket "
                        f"1.00 so the effect IS significant; prose contradicts numbers"
                    ),
                    fix_hint=(
                        "either rewrite the verbal claim to reflect the actual "
                        "significant finding, or re-verify the CI bounds against "
                        "the source paper"
                    ),
                    source=SOURCE,
                    timestamp=now,
                ))
                break  # one finding per verbal claim

        for cim in ABS_CI_RE.finditer(window):
            try:
                lo = float(cim.group(3))
                hi = float(cim.group(4))
            except ValueError:
                continue
            # Both bounds above 0 OR both below 0 → significant absolute diff;
            # verbal claim of "no difference" contradicts it.
            if (lo > 0.0 and hi > 0.0) or (lo < 0.0 and hi < 0.0):
                if abs(lo) < 0.05 or abs(hi) < 0.05:
                    continue  # bound near 0 is borderline
                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=Severity.WARN,
                    repo=None,
                    file=rel,
                    line=_line_of(text, m.start()),
                    detail=(
                        f"'{m.group(0)}' claim near {cim.group(1)} "
                        f"{cim.group(2)} ({lo} to {hi}) — CI doesn't bracket "
                        f"0 so the effect IS significant; prose contradicts numbers"
                    ),
                    fix_hint=(
                        "either rewrite the verbal claim, or re-verify the CI "
                        "bounds against the source paper"
                    ),
                    source=SOURCE,
                    timestamp=now,
                ))
                break
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
