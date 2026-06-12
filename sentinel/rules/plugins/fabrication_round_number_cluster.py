"""P1-fabrication-round-number-cluster: WARN on entries where too many
distinct number categories happen to land on suspiciously round values.

E156 Assurance Standard fabrication-detection family (BadScientist-inspired,
arXiv 2510.18003). Real meta-analytic data has irregular decimals: a
typical 7-sentence body quotes things like 'n=143 patients', 'p=0.038',
'OR=0.78 (0.65-0.93)'. Fabricated bodies often cluster on tidy values:
'n=100 patients, p=0.001, OR=1.00, follow-up 12.0 months'. Any ONE round
number is fine; THREE or more round numbers from DIFFERENT categories in
the same entry is a tell.

Heuristic — count distinct categories that fire:
  - cohort_round:  N (integer) ending in 00 or 000
  - p_round:       p = 0.0[01]+ (e.g. 0.01, 0.001, 0.0001) — too clean
  - or_round:      OR/HR/RR exactly 1.0[0]+ (no effect, perfect null)
  - or_double_round: OR/HR/RR ending in .00 or .50
  - follow_round:  follow-up length quoted as 12.0 / 24.0 / 36.0 months
  - pct_round:     percent values ending in exact 0/5 (e.g. 50%, 75%)

If ≥3 distinct categories fire in the same workbook entry block / single
review HTML body → WARN.

Files scanned: rewrite-workbook.txt (per [N/T] block) + *_REVIEW.html
(treating the whole file as one body, like claim_language does).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import path_allowed


ID = "P1-fabrication-round-number-cluster"
SEVERITY = Severity.WARN
SOURCE = ("F:\\e156\\docs\\assurance-standard.md#data-checking  "
          "(BadScientist family, arXiv 2510.18003)")
SCOPE = "repo"

MAX_FILE_BYTES = 10_000_000
MIN_CATEGORIES_TO_FIRE = 3

# Each pattern targets one category. A finding in any pattern = one
# category fired. The rule fires when ≥3 categories fire in the same body.
PATTERNS: dict[str, re.Pattern] = {
    "cohort_round": re.compile(r"\bn\s*=\s*(\d+00)\b", re.IGNORECASE),
    "p_round": re.compile(r"\bp\s*[=<≤]\s*0\.0+1\b", re.IGNORECASE),
    "or_perfect_null": re.compile(r"\b(?:OR|HR|RR|IRR)\s*[=:]?\s*1\.0+\b", re.IGNORECASE),
    "or_double_round": re.compile(
        r"\b(?:OR|HR|RR|IRR)\s*[=:]?\s*\d+\.(?:00|50)\b", re.IGNORECASE),
    "follow_round": re.compile(
        r"\bfollow-?up\s*(?:of\s+)?\d+(?:\.0)?\s*(?:months?|years?)\b",
        re.IGNORECASE),
    "pct_round": re.compile(r"\b(?:[1-9]\d)?[05]\.0+\s*%", re.IGNORECASE),
}


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _iter_target_files(root: Path):
    for p in root.glob("*_REVIEW.html"):
        if not path_allowed(root, p):
            continue  # honor `scan --diff` changed-file scope
        yield p
    wb = root / "rewrite-workbook.txt"
    if wb.is_file():
        yield wb


def _categories_in(body: str) -> list[str]:
    """Return the list of categories that fired in this body."""
    out = []
    for cat, pat in PATTERNS.items():
        if pat.search(body):
            out.append(cat)
    return out


def _check_one_file(text: str, rel: str, now: datetime) -> List[Verdict]:
    verdicts: List[Verdict] = []

    if rel == "rewrite-workbook.txt":
        SEP = "=" * 70
        blocks = text.split(SEP)
        cursor = 0
        for i, blk in enumerate(blocks):
            blk_offset = cursor
            cursor += len(blk) + len(SEP)
            cats = _categories_in(blk)
            if len(cats) < MIN_CATEGORIES_TO_FIRE:
                continue
            hm = re.search(r"^\[(\d+)/\d+\]", blk, re.MULTILINE)
            entry_num = int(hm.group(1)) if hm else None
            verdicts.append(Verdict(
                rule_id=ID,
                severity=Severity.WARN,
                repo=None,
                file=rel,
                line=_line_of(text, blk_offset),
                detail=(
                    f"entry #{entry_num}: {len(cats)} suspicious round-number "
                    f"categories firing ({', '.join(cats)}) — possible "
                    f"fabrication tell, real data has irregular decimals"
                ),
                fix_hint=(
                    "verify the quoted values against the source paper; "
                    "real RCT outputs rarely cluster on tidy numbers"
                ),
                source=SOURCE,
                timestamp=now,
            ))
    else:
        # Treat each HTML file as one body.
        cats = _categories_in(text)
        if len(cats) >= MIN_CATEGORIES_TO_FIRE:
            verdicts.append(Verdict(
                rule_id=ID,
                severity=Severity.WARN,
                repo=None,
                file=rel,
                line=1,
                detail=(
                    f"{len(cats)} suspicious round-number categories "
                    f"firing ({', '.join(cats)}) — possible fabrication tell"
                ),
                fix_hint="verify the quoted values against the source",
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
