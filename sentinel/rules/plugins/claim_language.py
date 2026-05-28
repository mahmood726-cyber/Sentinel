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

Override mechanism (added 2026-05-25): operators can whitelist legitimate
uses by adding one of these markers to the file or workbook entry:

  <!-- sentinel:claim-language-allow -->                  (HTML)
  # sentinel:claim-language-allow                         (markdown / workbook)
  sentinel:claim-language-context: descriptive            (stronger; same effect)

File-scope marker (before any [N/T] block, or in any non-workbook file) →
skip the whole file. Entry-scope marker (inside an [N/T] block of the
workbook) → skip just that entry. Use sparingly — the goal is operator-
documented exceptions, not bulk silencing.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P0-claim-language-workbook"
# Default severity is WARN across all files. BLOCK promotion is opt-in
# via SENTINEL_CLAIM_LANGUAGE_BLOCK=1 (workbook-only — rendered HTML
# always stays WARN even with the flag because those are auto-generated
# artifacts; fix the source, not the render).
#
# Phase-3 Q (2026-05-25): the path to BLOCK is shipped; the live baseline
# (1293 firings on the workbook) is too noisy to default-on without a
# substantial content cleanup pass first. Operator turns it on per-session
# once they've handled enough overrides.
SEVERITY = Severity.WARN
SOURCE = "F:\\e156\\docs\\assurance-standard.md#4-claim-language-checking"
SCOPE = "repo"

import os as _os
_BLOCK_OPT_IN = _os.environ.get("SENTINEL_CLAIM_LANGUAGE_BLOCK") == "1"


def _severity_for(rel: str) -> "Severity":
    """Per-file severity. With SENTINEL_CLAIM_LANGUAGE_BLOCK=1, the
    workbook gets BLOCK while rendered HTML stays WARN. Without the flag,
    everything stays WARN."""
    if _BLOCK_OPT_IN and rel == "rewrite-workbook.txt":
        return Severity.BLOCK
    return Severity.WARN

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

# Comparative-confidence overclaim — closes the synonym-evasion hole
# (2026-05-28 red-team #2): strong directional language that uses NO banned
# trigger word, e.g. "clearly reduces", "markedly improves", "strong signal".
# Always WARN (higher-FP heuristic than the causal list); operator overrides
# and <script> skipping still apply.
INTENSIFIER_CAUSAL_RE = re.compile(
    r"\b(clearly|markedly|robustly|strongly|dramatically|substantially|"
    r"convincingly|unequivocally|decisively|powerfully)\s+"
    r"(reduc\w+|increas\w+|improv\w+|lower\w+|rais\w+|prevent\w+|protect\w+|"
    r"cut\w+|boost\w+|worsen\w+)\b",
    re.IGNORECASE,
)
STRONG_EVIDENCE_RE = re.compile(
    r"\b(strong|compelling|overwhelming|robust|marked|dramatic|unequivocal)\s+"
    r"(signal|evidence|association|effect|benefit|protection|reduction)\b",
    re.IGNORECASE,
)

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

# Per-entry / per-file override marker. Operators can whitelist legitimate
# uses of certainty/overclaim language (e.g. "confirmed cases" in a public-
# health audit, "eliminates wrangling" in a software description) by adding
# one of these markers to the file or workbook entry:
#
#   <!-- sentinel:claim-language-allow -->                  (HTML)
#   # sentinel:claim-language-allow                         (markdown/workbook)
#   sentinel:claim-language-allow                            (anywhere in metadata)
#   sentinel:claim-language-context: descriptive             (stronger, same effect)
#
# File-scope marker → skip the whole file. Entry-scope marker (inside the
# [N/T] to next-SEP block in rewrite-workbook.txt) → skip just that entry.
#
# Use sparingly. The point is operator-documented exceptions, not bulk silencing.
OVERRIDE_MARKER_RE = re.compile(
    r"sentinel:claim-language(?:-allow|-context:\s*\w+)",
    re.IGNORECASE,
)

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


def _entry_blocks_with_overrides(text: str, rel: str) -> set[tuple[int, int]]:
    """For the workbook only: return the set of (start, end) char offsets of
    [N/T] entry blocks that contain a per-entry override marker. Findings
    inside those ranges are suppressed."""
    if rel != "rewrite-workbook.txt":
        # Only the workbook has [N/T] entry blocks separated by 70 "=" chars.
        return set()
    SEP = "=" * 70
    overrides: set[tuple[int, int]] = set()
    cursor = 0
    while True:
        end = text.find(SEP, cursor + 1)
        block = text[cursor:end if end >= 0 else len(text)]
        if OVERRIDE_MARKER_RE.search(block):
            overrides.add((cursor, end if end >= 0 else len(text)))
        if end < 0:
            break
        cursor = end + len(SEP)
    return overrides


def _check_one_file(text: str, rel: str, now: datetime) -> List[Verdict]:
    verdicts: List[Verdict] = []

    # Skip our own doc files — they explicitly *list* the banned words
    # to document the rule. Don't false-positive on the rule's own docs.
    if rel.startswith("docs/assurance-standard"):
        return verdicts
    if "claim-language" in rel or "claim_language" in rel:
        return verdicts

    # File-scope override: skip the whole file.
    if OVERRIDE_MARKER_RE.search(text):
        # An entry-scope marker is INSIDE a [N/T] block; a file-scope marker
        # is OUTSIDE any block (header, footer, prelude). For non-workbook
        # files we use the simpler heuristic: any marker present → skip file.
        if rel != "rewrite-workbook.txt":
            return verdicts
        # For the workbook, only skip the whole file if the marker is in
        # the pre-entry header. Detect by checking if the FIRST marker
        # appears before the first [N/T] block.
        first_marker = OVERRIDE_MARKER_RE.search(text).start()
        first_entry = re.search(r"^\[\d+/\d+\]", text, re.MULTILINE)
        if first_entry is None or first_marker < first_entry.start():
            return verdicts

    # Entry-scope overrides: collect the ranges to suppress (workbook only).
    override_ranges = _entry_blocks_with_overrides(text, rel)

    def _is_overridden(offset: int) -> bool:
        return any(s <= offset < e for s, e in override_ranges)

    # 1a. WARN on soft-overclaim (confirms/confirmed)
    for m in OVERCLAIM_SOFT_RE.finditer(text):
        if _is_overridden(m.start()):
            continue
        pre = text[max(0, m.start() - 500):m.start()]
        if pre.rfind("<script") > pre.rfind("</script>"):
            continue
        verdicts.append(Verdict(
            rule_id=ID,
            severity=_severity_for(rel),
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
        if _is_overridden(m.start()):
            continue
        # Skip if inside a <script> block (likely a JS variable / API doc)
        # Heuristic: previous 200 chars contain <script and no </script
        pre = text[max(0, m.start() - 500):m.start()]
        if pre.rfind("<script") > pre.rfind("</script>"):
            continue
        verdicts.append(Verdict(
            rule_id=ID,
            severity=_severity_for(rel),
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

    # 1c. WARN on comparative-confidence overclaim (intensifier + directional
    # verb, or "strong/compelling <evidence-noun>") with no banned trigger word.
    for rx in (INTENSIFIER_CAUSAL_RE, STRONG_EVIDENCE_RE):
        for m in rx.finditer(text):
            if _is_overridden(m.start()):
                continue
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
                    f"comparative-confidence overclaim {m.group(0)!r} — strong "
                    f"directional language without an uncertainty qualifier in a "
                    f"156-word meta-analytic body"
                ),
                fix_hint=(
                    "soften to 'was associated with' / 'suggests' / 'is "
                    "consistent with', and state the certainty (GRADE) and the "
                    "interval; reserve 'strong'/'clear' for high-certainty evidence"
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
            # Entry-scope override marker → suppress THIS entry's findings
            if OVERRIDE_MARKER_RE.search(blk):
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
                    severity=_severity_for(rel),
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
                severity=_severity_for(rel),
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
