"""P0-citation-cascade: BLOCK structurally-invalid DOIs; WARN on potentially
hallucinated citations.

E156 Assurance Standard "Made-up citations" risk class. Per the standard
(F:\\e156\\docs\\assurance-standard.md), every citation in an e156 paper or
capsule should resolve through one of CrossRef / Semantic Scholar / OpenAlex
/ source PDF. A made-up citation is an automatic fail.

Phase 1 (this rule) ships a STATIC subset of that cascade — pure regex over
the doc text, no external HTTP calls. It catches the structural-validity
class which is the high-confidence half of the standard:

  BLOCK: a DOI string that doesn't match the `10.PREFIX/SUFFIX` format
         (10.NNNN/anything-no-whitespace). This is the same defect family
         as the Python-None-into-JS leak — a parse-time tell that the
         reference was never grounded in a real registry.

  WARN: a reference line that looks like a citation (has 'et al.' or a year
        in parens) but contains NO DOI, NO PMID, and NO URL. Suspicious;
        could be a hand-written placeholder.

Phase 2 (deferred) will add the actual CrossRef / Semantic Scholar / OpenAlex
HTTP cascade — Sentinel doesn't currently make network calls in commit-time
rules, so adding live lookups needs a per-repo opt-in flag and a cache.

Files scanned: *.md, *.html, rewrite-workbook.txt — anything with a
References / Bibliography section or a doi:/DOI: prefix anywhere.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P0-citation-cascade"
SEVERITY = Severity.BLOCK
SOURCE = "F:\\e156\\docs\\assurance-standard.md#1-citation-verification"
SCOPE = "repo"

MAX_FILE_BYTES = 5_000_000

# Valid DOI shape: 10.<registrant 4+ digits>/<suffix, no whitespace>
# Citation-cascade BLOCK case: anything matched as "doi:" or "DOI:" or
# "https://doi.org/" that LOOKS LIKE AN ATTEMPTED DOI (contains both a
# "." and a "/") but does NOT match the valid shape.
#
# We pre-filter the candidate to weed out obvious non-attempts:
#   - shorter than 6 chars (e.g. "-", "?", "TBD")
#   - no "/" (e.g. "Pending", "TODO", "document.getElementById")
#   - matches a known-placeholder allowlist (Pending, TBD, n/a, etc.)
# These would never have been REAL attempted DOIs, so flagging them as
# malformed adds noise without finding real hallucinated citations.
DOI_PREFIX_RE = re.compile(
    r"(?:^|[\s\(\[\{>;,])"
    r"(?:doi[:=]\s*|DOI[:=]\s*|https?://(?:dx\.)?doi\.org/)"
    r"(\S+?)"
    r"(?=[\s)\]}<;,\"']|\.\s|\.$|$)",
    re.MULTILINE,
)

VALID_DOI_RE = re.compile(r"^10\.\d{4,9}/\S+$")

PLACEHOLDER_DOI_VALUES = frozenset({
    "-", "?", "tbd", "todo", "pending", "n/a", "none", "null", "_", "",
    "10.x/y", "10.xxxx/yyyy",
})

# E156 capsule convention: unpublished micro-papers carry the internal
# namespace `10.156/<slug>` as a stable pre-registration identifier (the
# "156" matches the E156 format name). These are deliberate placeholders,
# not malformed real-DOI attempts — same category as 10.x/y, but with a
# variable suffix so they can't be enumerated as fixed values.
# Confirmed intentional by the operator (2026-05-28) after the portfolio
# scan surfaced 134 such capsules in AfricaRCT.
E156_PLACEHOLDER_DOI_RE = re.compile(r"^10\.156/\S+$")


def _looks_like_attempted_doi(candidate: str) -> bool:
    """True if the candidate looks like SOMEONE TRIED to write a DOI but got
    it wrong. False for clearly-non-DOI strings that happened to follow a
    'doi:' substring (JS identifiers, template placeholders, prose)."""
    c = candidate.strip(".,)]\"'").rstrip(".")
    if len(c) < 6:
        return False
    if c.lower() in PLACEHOLDER_DOI_VALUES:
        return False
    if E156_PLACEHOLDER_DOI_RE.match(c):
        return False  # E156 capsule pre-registration namespace
    if "/" not in c:
        # Real DOIs always contain at least one slash. A capture without "/"
        # is overwhelmingly likely to be a JS identifier or template token.
        return False
    if "." not in c:
        return False
    return True

# Hallucinated-citation heuristic: a line that looks like a reference
# (numbered or contains " et al" or contains a 4-digit year in parens)
# but has zero DOI, PMID, or http(s) URL.
REFERENCE_LINE_RE = re.compile(
    r"^\s*(?:\d+\.\s+|\[\d+\]\s+|-\s+)"  # numbered or bulleted
    r".*",
    re.MULTILINE,
)
HAS_LOCATOR_RE = re.compile(
    r"\b(?:doi[:=]|DOI[:=]|PMID[:=]?|PMC\d|https?://)",
    re.IGNORECASE,
)
HAS_AUTHOR_YEAR_RE = re.compile(r"\bet al\b|\(\d{4}[a-z]?\)", re.IGNORECASE)

EXCLUDE_DIRS = frozenset((
    "node_modules", "__pycache__", ".git", ".pytest_cache", ".venv",
    "venv", "build", "dist", ".tox", ".mypy_cache",
))
INCLUDE_EXT = frozenset((".md", ".html", ".txt", ".rst"))
INCLUDE_NAMES = frozenset(("rewrite-workbook.txt",))


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _iter_doc_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(d in EXCLUDE_DIRS for d in path.parts):
            continue
        if path.name in INCLUDE_NAMES or path.suffix.lower() in INCLUDE_EXT:
            yield path


def _check_one_file(text: str, rel: str, now: datetime) -> List[Verdict]:
    verdicts: List[Verdict] = []

    # 1. BLOCK on malformed DOIs (only flag attempts that look real-ish)
    for m in DOI_PREFIX_RE.finditer(text):
        candidate = m.group(1).strip(".,)]\"'").rstrip(".")
        if not _looks_like_attempted_doi(candidate):
            continue
        if not VALID_DOI_RE.match(candidate):
            verdicts.append(Verdict(
                rule_id=ID,
                severity=Severity.BLOCK,
                repo=None,
                file=rel,
                line=_line_of(text, m.start()),
                detail=(
                    f"DOI string {candidate!r} does not match the "
                    f"10.<registrant>/<suffix> format. Verify against "
                    f"CrossRef before merging — bad DOIs typically signal "
                    f"a hallucinated or placeholder reference."
                ),
                fix_hint=(
                    "look the cited paper up on doi.org or crossref.org; "
                    "if no real DOI exists, the citation should not be "
                    "included as a verified reference"
                ),
                source=SOURCE,
                timestamp=now,
            ))

    # 2. WARN on reference-looking lines that have no locator
    # Limit to files that actually have a References / Bibliography section
    # so we don't false-positive on random numbered lists in arbitrary docs.
    has_refs_section = bool(re.search(
        r"^#{1,6}\s+(?:References|Bibliography|Works cited)\b",
        text, re.MULTILINE | re.IGNORECASE,
    ))
    if has_refs_section:
        for m in REFERENCE_LINE_RE.finditer(text):
            line = m.group(0)
            if not HAS_AUTHOR_YEAR_RE.search(line):
                continue
            if HAS_LOCATOR_RE.search(line):
                continue
            # WARN — looks like a citation but has no DOI/PMID/URL
            verdicts.append(Verdict(
                rule_id=ID,
                severity=Severity.WARN,
                repo=None,
                file=rel,
                line=_line_of(text, m.start()),
                detail=(
                    f"Reference line has author/year shape but no "
                    f"DOI/PMID/URL: {line.strip()[:120]!r}"
                ),
                fix_hint=(
                    "add a DOI (doi:10.X/Y), PMID, or canonical URL so the "
                    "citation can be resolved through CrossRef / Semantic "
                    "Scholar / OpenAlex per the Assurance Standard"
                ),
                source=SOURCE,
                timestamp=now,
            ))

    return verdicts


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    root = ctx.repo_root
    for path in _iter_doc_files(root):
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
