"""P1-claim-grounding: WARN when a doc states quantitative effect claims but
cites NO resolvable source identifier anywhere in the document.

Companion to citation_cascade / citation_resolution. Those check the *reference
list* (DOI shape, DOI resolution). This checks the opposite failure: a capsule
that asserts effect sizes ("HR 0.74 (95% CI 0.65 to 0.85)", "reduced events by
30%", "p < 0.001") in its body but carries no DOI / PMID / NCT / URL at all — an
ungrounded claim. It is the document-level mirror of Overmind's claim-grounding
witness (overmind.evidence.grounding), which does the claim-to-corpus resolution.

WARN, not BLOCK, per the leaked_secret promotion precedent: ship at WARN, and only
promote to BLOCK after a portfolio sweep shows zero false positives.

FALSE-POSITIVE DISCIPLINE:
  - Inert on any doc with NO quantitative effect claims (zero findings) — cannot
    regress the vast majority of existing pushes.
  - A single resolvable locator (DOI/PMID/NCT/http) anywhere in the doc clears it:
    claim-level grounding is the witness's job, not a commit-time regex's.
  - Files carrying ``sentinel:skip-file`` are skipped (negative-test fixtures).
  - Only .md / .html / .txt / .rst capsule-style docs are scanned.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict

ID = "P1-claim-grounding"
SEVERITY = Severity.WARN
SOURCE = "F:\\e156\\docs\\assurance-standard.md#1-citation-verification"
SCOPE = "repo"

MAX_FILE_BYTES = 5_000_000
SKIP_MARKER = "sentinel:skip-file"

EXCLUDE_DIRS = frozenset((
    "node_modules", "__pycache__", ".git", ".pytest_cache", ".venv",
    "venv", "build", "dist", ".tox", ".mypy_cache",
))
INCLUDE_EXT = frozenset((".md", ".html", ".txt", ".rst"))

# Quantitative effect-claim tells. Any one match makes the doc "claim-bearing".
# CASE-SENSITIVE on the abbreviations: lowercase "or 3" / "rr 2" are English, not
# effect estimates. The abbreviation must be UPPERCASE and a standalone token, and
# be followed by a ratio-shaped value (a decimal, or an explicit = / :) so prose like
# "OR 3 other options" does not match. (FP found 2026-06-03 on overmind docs: "or 3".)
CLAIM_PATTERNS = (
    re.compile(r"\b(?:aHR|aOR|HR|RR|OR)\b\s*(?:[=:]\s*)?\d+\.\d"),     # HR 0.74 / OR=1.2
    re.compile(r"\b(?:aHR|aOR|HR|RR|OR)\b\s*[=:]\s*\d"),                # HR = 2 (explicit)
    re.compile(r"\b(?:hazard|risk|odds)\s+ratio\b", re.IGNORECASE),
    re.compile(r"\b95\s*%\s*CI\b", re.IGNORECASE),
    re.compile(r"\bp\s*[<>=]\s*0?\.\d", re.IGNORECASE),
    # "...by 30%" (relative reduction/increase phrasing)
    re.compile(r"\bby\s+\d+(?:\.\d+)?\s*%", re.IGNORECASE),
    # "30% reduction / increase / lower / relative ..."
    re.compile(r"\b\d+(?:\.\d+)?\s*%\s+(?:reduction|increase|decrease|relative|lower|higher)", re.IGNORECASE),
)

# A resolvable source locator. Mirrors citation_cascade's locator set.
LOCATOR_RE = re.compile(
    r"\b(?:doi[:=]|DOI[:=]|https?://(?:dx\.)?doi\.org/|10\.\d{4,9}/\S+|"
    r"PMID[:=]?\s*\d|PMC\d|NCT\d{8}|https?://)",
    re.IGNORECASE,
)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _iter_doc_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(d in EXCLUDE_DIRS for d in path.parts):
            continue
        if path.suffix.lower() in INCLUDE_EXT:
            yield path


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    root = ctx.repo_root
    verdicts: List[Verdict] = []
    for path in _iter_doc_files(root):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if SKIP_MARKER in text:
            continue

        # A single locator anywhere clears the doc — conservative by design.
        if LOCATOR_RE.search(text):
            continue

        first_claim = None
        claim_hits = 0
        for pat in CLAIM_PATTERNS:
            for m in pat.finditer(text):
                claim_hits += 1
                if first_claim is None:
                    first_claim = m
        if not claim_hits or first_claim is None:
            continue

        rel = path.relative_to(root).as_posix()
        verdicts.append(Verdict(
            rule_id=ID,
            severity=Severity.WARN,
            repo=str(root),
            file=rel,
            line=_line_of(text, first_claim.start()),
            detail=(
                f"document states {claim_hits} quantitative effect claim(s) "
                f"(e.g. {first_claim.group(0).strip()!r}) but carries no resolvable "
                f"source identifier (DOI/PMID/NCT/URL) anywhere - the claims are ungrounded."
            ),
            fix_hint=(
                "add the DOI/PMID/NCT of the source each effect estimate comes from, "
                "or run the Overmind claim-grounding witness (overmind ground) to bind "
                "each claim to a corpus record"
            ),
            source=SOURCE,
            timestamp=now,
        ))
    return verdicts
