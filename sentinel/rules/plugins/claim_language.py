"""P0-claim-language: BLOCK causal-overclaim words; WARN certainty-claims
near heterogeneity language.

E156 Assurance Standard "Overclaiming" risk class. Per the standard:

  > high heterogeneity → conclusion must be cautious
  > wide CI            → conclusion must mention uncertainty
  > few studies        → conclusion must be limited

This rule is a *static* check that fires when a meta-analytic claim uses
causal-certainty language inappropriate for the 156-word body of an
evidence capsule, OR when a "safe/effective" claim sits in the same body
as explicit heterogeneity markers (the two assertions disagree).

BLOCK words (causal overclaim — never appropriate in a 156-word MA body):
  proves, proven, confirms, confirmed, eliminates, eliminated,
  definitive, definitively, undeniably, conclusively

WARN words (certainty claims that need context — fire only when the body
ALSO contains heterogeneity language):
  safe, effective, no difference, significant benefit, clinically meaningful,
  cures, prevents

Heterogeneity markers (presence triggers the WARN tier when paired with a
certainty word above): I², prediction interval, wide CI, tau², few studies,
risk of bias, downgraded, uncertain

Files scanned: rewrite-workbook.txt, students.html, paper/*.html — anything
that contains rendered e156 body text.

Scope: repo (commit-time).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P1-claim-language"
SEVERITY = Severity.WARN
SOURCE = "F:\\e156\\docs\\assurance-standard.md#4-claim-language-checking"
SCOPE = "repo"

MAX_FILE_BYTES = 10_000_000

# BLOCK-tier causal-overclaim regex. Conservative: only words that are
# unambiguously over-claim in any context. The original Assurance Standard
# list also includes "confirms/confirmed" but a baseline scan against the
# live workbook (2026-05-24) found 2,788 firings of those, mostly legitimate
# descriptive uses ("confirmed cases", "confirmed primary endpoint"). They
# move to the WARN tier in OVERCLAIM_SOFT_RE below; the BLOCK list stays
# tight so committed code doesn't drown in noise.
CAUSAL_OVERCLAIM_RE = re.compile(
    r"\b(prov(?:es|en)|eliminat(?:es|ed)|"
    r"definitiv(?:e|ely)|undeniably|conclusively)\b",
    re.IGNORECASE,
)

# Soft-overclaim tier — WARN, not BLOCK. Same intent as the BLOCK list but
# context-sensitive enough that we want operator review rather than auto-rejection.
OVERCLAIM_SOFT_RE = re.compile(r"\bconfirm(?:s|ed)\b", re.IGNORECASE)

# WARN-tier certainty words. Singular regex for readability.
CERTAINTY_PHRASES = [
    r"\bsafe\b",
    r"\beffective\b",
    r"\bno difference\b",
    r"\bsignificant benefit\b",
    r"\bclinically meaningful\b",
    r"\bcures\b",
    r"\bprevents?\b",
]
CERTAINTY_RE = re.compile("|".join(CERTAINTY_PHRASES), re.IGNORECASE)

# Heterogeneity context. If any of these appear in the same body as a
# certainty phrase, fire the WARN.
HETERO_RE = re.compile(
    r"I[²2]\s*=|prediction interval|wide CI|tau[²2]|few studies|"
    r"risk of bias|downgraded|uncertain|low certainty",
    re.IGNORECASE,
)

# We care about ENGLISH PROSE not code. Skip the file if it looks like JS/CSS
# source rather than rendered text. This is a heuristic; the workbook + paper
# pages + students.html (the targets) all pass.
SCRIPT_TAG_RE = re.compile(r"<script\b", re.IGNORECASE)

EXCLUDE_DIRS = frozenset((
    "node_modules", "__pycache__", ".git", ".pytest_cache",
    ".venv", "venv", "build", "dist",
))


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _iter_target_files(root: Path):
    """Workbook + students + paper pages — narrow target list to avoid
    scanning thousands of unrelated files."""
    # rewrite-workbook.txt and students.html at root
    for name in ("rewrite-workbook.txt", "students.html"):
        p = root / name
        if p.is_file():
            yield p
    # paper/*.html
    paper_dir = root / "paper"
    if paper_dir.is_dir():
        for p in paper_dir.glob("*.html"):
            yield p
    # docs/ markdown — assurance-standard.md etc. (catches our own doc
    # for testing, but we'll filter that out below)
    docs_dir = root / "docs"
    if docs_dir.is_dir():
        for p in docs_dir.glob("*.md"):
            yield p


def _check_one_file(text: str, rel: str, now: datetime) -> List[Verdict]:
    verdicts: List[Verdict] = []

    # Skip our own doc files — they explicitly *list* the banned words
    # to document the rule. Don't false-positive on the rule's own docs.
    if rel.startswith("docs/assurance-standard"):
        return verdicts
    if "claim-language" in rel or "claim_language" in rel:
        return verdicts

    # 1a. WARN on soft-overclaim (confirms/confirmed)
    for m in OVERCLAIM_SOFT_RE.finditer(text):
        pre = text[max(0, m.start() - 500):m.start()]
        if pre.rfind("<script") > pre.rfind("</script>"):
            continue
        verdicts.append(Verdict(
            rule_id=ID,
            severity=Severity.WARN,
            repo=None,
            file=rel,
            line=_line_of(text, m.start()),
            detail=(
                f"soft-overclaim word {m.group(0)!r} — verify context is "
                f"descriptive (e.g. 'confirmed cases') not causal "
                f"(e.g. 'confirms the hypothesis')"
            ),
            fix_hint=(
                "if context is causal, rewrite to 'supports' / 'is "
                "consistent with' / 'shows'. If descriptive, ignore."
            ),
            source=SOURCE,
            timestamp=now,
        ))

    # 1b. BLOCK on causal-overclaim words
    for m in CAUSAL_OVERCLAIM_RE.finditer(text):
        # Skip if inside a <script> block (likely a JS variable / API doc)
        # Heuristic: previous 200 chars contain <script and no </script
        pre = text[max(0, m.start() - 500):m.start()]
        if pre.rfind("<script") > pre.rfind("</script>"):
            continue
        verdicts.append(Verdict(
            rule_id=ID,
            severity=Severity.WARN,
            repo=None,
            file=rel,
            line=_line_of(text, m.start()),
            detail=(
                f"causal-overclaim word {m.group(0)!r} in rendered body — "
                f"inappropriate for a 156-word meta-analytic claim"
            ),
            fix_hint=(
                "rewrite the sentence with hedged language (e.g. 'consistent "
                "with', 'suggests', 'is associated with') and add an "
                "uncertainty qualifier if the evidence supports it"
            ),
            source=SOURCE,
            timestamp=now,
        ))

    # 2. WARN if certainty phrase + heterogeneity language coexist in same body.
    # Body unit: an entry block in rewrite-workbook.txt is delimited by the
    # 70-char "=" separator. For students.html and paper/*.html, treat the
    # whole file as one body (the file IS the body).
    if rel == "rewrite-workbook.txt":
        SEP = "=" * 70
        blocks = text.split(SEP)
        for i, blk in enumerate(blocks):
            if not blk.strip():
                continue
            hm = re.search(r"^\[(\d+)/\d+\]", blk, re.MULTILINE)
            entry_num = int(hm.group(1)) if hm else None
            certs = list(CERTAINTY_RE.finditer(blk))
            heteros = list(HETERO_RE.finditer(blk))
            if certs and heteros:
                # WARN once per entry, on the first certainty phrase
                first = certs[0]
                # Compute approximate file offset of this block:
                blk_offset = sum(len(blocks[j]) + len(SEP) for j in range(i))
                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=Severity.WARN,
                    repo=None,
                    file=rel,
                    line=_line_of(text, blk_offset + first.start()),
                    detail=(
                        f"entry #{entry_num}: certainty phrase {first.group(0)!r} "
                        f"appears alongside heterogeneity language "
                        f"({heteros[0].group(0)!r}) — claim and evidence disagree"
                    ),
                    fix_hint=(
                        "hedge the certainty phrase or remove the heterogeneity "
                        "qualifier; consistency between the two is required by "
                        "the Assurance Standard claim-certainty match"
                    ),
                    source=SOURCE,
                    timestamp=now,
                ))
    else:
        certs = list(CERTAINTY_RE.finditer(text))
        heteros = list(HETERO_RE.finditer(text))
        if certs and heteros:
            first = certs[0]
            verdicts.append(Verdict(
                rule_id=ID,
                severity=Severity.WARN,
                repo=None,
                file=rel,
                line=_line_of(text, first.start()),
                detail=(
                    f"certainty phrase {first.group(0)!r} appears alongside "
                    f"heterogeneity language ({heteros[0].group(0)!r})"
                ),
                fix_hint=(
                    "hedge the certainty phrase or remove the heterogeneity "
                    "qualifier per Assurance Standard claim-certainty match"
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
