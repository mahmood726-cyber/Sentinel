"""P1-fabrication-orphan-trial: WARN when an NCT id is mentioned in the
rendered body but has no matching entry in realData.

E156 Assurance Standard fabrication-detection family (BadScientist-inspired,
arXiv 2510.18003). The "orphan trial" tell is when prose says "We pooled
trials X, Y, Z" but the actual data block only contains X and Y. Either Z
was fabricated, or it was dropped during data extraction without updating
the prose. Either way the artifact is internally inconsistent and shouldn't
ship.

Scope is intentionally narrow:
  - Only flag NCT ids (NCT + 8 digits) — they're unambiguous identifiers,
    unlike trial acronyms which legitimately repeat across reports.
  - Only fire on files that have BOTH (a) NCT mentions in body text, AND
    (b) a realData block — without a realData block we have nothing to
    cross-check against.
  - Conservative: skip NCT ids in href="..." or <script> contexts (those
    are typically navigation/registry links, not data claims).
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
    REALDATA_RE,
)


ID = "P1-fabrication-orphan-trial"
SEVERITY = Severity.WARN
SOURCE = ("F:\\e156\\docs\\assurance-standard.md#data-provenance-match  "
          "(BadScientist family, arXiv 2510.18003)")
SCOPE = "repo"

MAX_FILE_BYTES = 10_000_000

# NCT id matcher. Use group so we can collect the bare id.
NCT_RE = re.compile(r"\bNCT(\d{8})\b")

# Contexts where an NCT id is navigation/registry-pointing, not a data claim.
# If the NCT appears inside one of these, skip it.
NAV_CONTEXT_RE = re.compile(
    r"""(?:href\s*=\s*['"][^'"]*|ctgovUrl\s*[:=]\s*['"][^'"]*|"""
    r"""nctAcronyms\s*[:=]\s*\{[^}]*|clinicaltrials\.gov/[A-Za-z0-9/-]*)""",
    re.IGNORECASE | re.DOTALL,
)


def _iter_html_files(root: Path):
    for p in root.glob("*_REVIEW.html"):
        yield p


def _check_one_file(text: str, rel: str, now: datetime) -> List[Verdict]:
    verdicts: List[Verdict] = []

    # Skip files without a realData block — nothing to cross-check.
    if not REALDATA_RE.search(text):
        return verdicts

    # Collect the realData NCT keys
    realdata_ncts: set[str] = set()
    for nct, _entry, _ofs in _iter_realdata_entries(text):
        # nct from the parser is like "NCT12345678"
        m = NCT_RE.match(nct)
        if m:
            realdata_ncts.add(m.group(1))

    if not realdata_ncts:
        # If we can't extract any NCTs from realData, can't cross-check.
        return verdicts

    # Find body-mentioned NCT ids that aren't in realData.
    # Strip out nav contexts first to suppress href/script noise.
    body_text = NAV_CONTEXT_RE.sub("", text)
    seen_in_body: set[str] = set()
    for m in NCT_RE.finditer(body_text):
        nct_digits = m.group(1)
        if nct_digits in realdata_ncts:
            continue
        if nct_digits in seen_in_body:
            continue
        seen_in_body.add(nct_digits)
        # The offset is into the stripped text; map back to the original by
        # finding the first occurrence in the original text.
        orig_idx = text.find(f"NCT{nct_digits}")
        line = _line_of(text, orig_idx if orig_idx >= 0 else m.start())
        verdicts.append(Verdict(
            rule_id=ID,
            severity=Severity.WARN,
            repo=None,
            file=rel,
            line=line,
            detail=(
                f"NCT{nct_digits} mentioned in body but not in realData — "
                f"orphan trial reference: either the trial was dropped during "
                f"extraction (update prose) or the citation is fabricated"
            ),
            fix_hint=(
                f"verify NCT{nct_digits} against ClinicalTrials.gov; either "
                f"add it to realData with full extracted fields, or remove "
                f"the prose citation if it was inherited from a different paper"
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
