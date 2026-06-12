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
from sentinel.io.git_files import iter_tree_or_filter

ID = "P1-claim-grounding"
SEVERITY = Severity.WARN
SOURCE = "F:\\e156\\docs\\assurance-standard.md#1-citation-verification"
SCOPE = "repo"

MAX_FILE_BYTES = 5_000_000
SKIP_MARKER = "sentinel:skip-file"

EXCLUDE_DIRS = frozenset((
    "node_modules", "__pycache__", ".git", ".pytest_cache", ".venv",
    "venv", "build", "dist", ".tox", ".mypy_cache",
    # Agent/tool working-state dirs hold generated diffs/reports that quote effect
    # numbers from elsewhere (e.g. .workflow-state/findings_diff.md held 160 such
    # "claims" in a 2026-06-03 portfolio sweep) — generated, not authored capsules.
    ".workflow-state",
    # Frozen historical copies: old versions, release snapshots. These are not
    # the live authored capsule, so re-auditing their citation grounding is pure
    # noise (a single app's `archive/` held ~70 such "claims" in a 2026-06-04
    # allmeta sweep). `backup_*` dirs handled by the prefix check below.
    "archive", "release-snapshots",
))
# Path-part prefixes that mark a frozen/backup copy (e.g. backup_2026_01_13).
# Exact-name EXCLUDE_DIRS can't catch these because the date suffix varies.
FROZEN_DIR_PREFIXES = ("backup_", "backup-")
INCLUDE_EXT = frozenset((".md", ".html", ".txt", ".rst"))

# Tool-generated output artifacts that QUOTE prior findings (which may themselves
# contain effect-claim text like "hazard ratio") and therefore self-trip this rule.
# They are machine-written logs, not authored capsules — excluding them removes
# self-referential noise. (Observed 2026-06-03: this rule WARNed on Sentinel's own
# sentinel-findings.md because it quoted an earlier finding.)
EXCLUDE_NAMES = frozenset((
    "sentinel-findings.md",
    "stuck_failures.md",
))
# Generated-report filename SHAPES (machine-written docs that quote prior findings
# and so self-trip this rule). Parametrised because the exact-name list above was
# edited twice — per rules.md, a hardcoded batch list edited >once must become a
# pattern. gitignore-awareness isn't available (RepoContext carries only repo_root),
# so match the conventional generated-report name shapes instead: *findings*.md,
# *nightly*.md, stuck_failures*, progress.md, aggregate*, review_findings*.
EXCLUDE_NAME_RE = re.compile(
    r"findings|nightly|stuck[_-]?failures|^progress\.|aggregate", re.IGNORECASE
)

# Quantitative effect-claim tells. Any one match makes the doc "claim-bearing".
# CASE-SENSITIVE on the abbreviations: lowercase "or 3" / "rr 2" are English, not
# effect estimates. The abbreviation must be UPPERCASE and a standalone token, and
# be followed by a ratio-shaped value (a decimal, or an explicit = / :) so prose like
# "OR 3 other options" does not match. (FP found 2026-06-03 on overmind docs: "or 3".)
#   The `(?<!\d )` negative lookbehind rejects "<number> OR <number>" — uppercase
#   "OR" as the English conjunction between two figures ("5 OR 3.5 ways") is not an
#   odds-ratio estimate. A real estimate ("adjusted OR 1.45") is not preceded by a
#   bare number. (FP found 2026-06-04.)
CLAIM_PATTERNS = (
    re.compile(r"(?<!\d )\b(?:aHR|aOR|HR|RR|OR)\b\s*(?:[=:]\s*)?\d+\.\d"),  # HR 0.74 / OR=1.2
    re.compile(r"(?<!\d )\b(?:aHR|aOR|HR|RR|OR)\b\s*[=:]\s*\d"),            # HR = 2 (explicit)
    # Spelled-out "hazard/risk/odds ratio" only counts as a quantitative CLAIM when a
    # number sits next to it (same sentence span). A bare phrase with no value is a
    # methodological mention or an illustrative example — e.g. "hazard ratio edge case
    # failed" in a design-doc table — not an ungrounded estimate. (FP 2026-06-05 on
    # overmind docs/specs/2026-04-07-memory-and-dreaming-design.md.) Numeric forms with
    # an abbreviation (HR 0.74) are already covered by the two patterns above.
    re.compile(
        r"\b(?:hazard|risk|odds)\s+ratio\b[^\n.]{0,25}?\d"   # ...ratio of 0.74
        r"|\d[^\n.]{0,25}?\b(?:hazard|risk|odds)\s+ratio\b",  # a 0.74 hazard ratio
        re.IGNORECASE,
    ),
    # "95% CI" only counts as a claim tell when an actual interval value follows it
    # (a number or an opening bracket). Bare "95 % CI" in prose ("chapter 95 % CI of
    # the room", or 'CI' meaning continuous-integration) is not an estimate. (FP 2026-06-04.)
    re.compile(r"\b95\s*%\s*CI\b[\s:]*[\[(]?\s*[\d.]", re.IGNORECASE),
    re.compile(r"\bp\s*[<>=]\s*0?\.\d", re.IGNORECASE),
    # "...by 30%" (relative reduction/increase phrasing)
    re.compile(r"\bby\s+\d+(?:\.\d+)?\s*%", re.IGNORECASE),
    # "30% reduction / increase / lower / relative ..."
    re.compile(r"\b\d+(?:\.\d+)?\s*%\s+(?:reduction|increase|decrease|relative|lower|higher)", re.IGNORECASE),
)

# A resolvable source locator. Only SOURCE-SHAPED identifiers clear the doc — a
# generic URL (a logo/CDN image src, a localhost link, a tracking pixel) is NOT a
# resolvable citation and must not silence the rule (the dominant false-NEGATIVE
# before 2026-06-04: a bare `https?://` catch-all cleared any doc with any URL).
LOCATOR_RE = re.compile(
    r"(?:"
    r"doi\s*[:=]\s*10\.\d{4,9}/"                              # doi: 10.xxxx/...
    r"|https?://(?:dx\.)?doi\.org/10\.\d{4,9}/"               # DOI resolver URL
    r"|https?://pubmed\.ncbi\.nlm\.nih\.gov/\d"               # PubMed article URL
    r"|https?://(?:www\.)?clinicaltrials\.gov/\S*NCT\d{8}"    # ClinicalTrials.gov URL
    r"|https?://www\.crd\.york\.ac\.uk/prospero"             # PROSPERO URL
    r"|\bPMID\s*[:=]?\s*\d"                                   # PMID
    r"|\bPMC\d{5,8}\b"                                         # PMCID (real ones are 5-8 digits; not 'PMC1')
    r"|\bNCT\d{8}\b"                                           # ClinicalTrials.gov accession
    # bare DOI in a raw reference list. Kept (dropping it would over-warn capsules
    # that cite a raw DOI), but the suffix must be >=3 chars and not a version/build
    # token, so 'upgraded to 10.1234/version2' no longer counts as a citation.
    r"|\b10\.\d{4,9}/(?!(?:version|build|v)\d)[^\s\"'<>]{3,}"
    r")",
    re.IGNORECASE,
)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


# <script>/<style> bodies in an interactive tool's index.html are JS/CSS source,
# not empirical prose: `var q = p < 0.5 ? ...` trips the p-value pattern, a
# `const KNOWN = { RR: 1, OR: 1 }` lookup trips the ratio pattern, etc. These are
# the dominant false positives on calculator apps (2026-06-04 allmeta sweep).
# Blank the block bodies (keeping newlines so line numbers of any *prose* claim
# outside the block stay accurate) before claim detection.
_SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)


def _strip_code_blocks(text: str) -> str:
    return _SCRIPT_STYLE_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


# An interactive computational tool (calculator app) is not a claim-bearing
# document: its "95% CI" / "odds ratio" mentions are column headers, button
# tooltips, and method-description prose, not empirical findings that need a
# citation. Detect the data-entry surface a static manuscript never has — a
# <textarea> (paste-in data) or two or more form controls. (Found 2026-06-04:
# 16 allmeta calculator index.html files false-tripped this rule on UI chrome.)
_DATA_ENTRY_RE = re.compile(r"<(?:input|select|textarea)\b", re.IGNORECASE)
_TEXTAREA_RE = re.compile(r"<textarea\b", re.IGNORECASE)


def _is_interactive_tool(text: str) -> bool:
    if _TEXTAREA_RE.search(text):
        return True
    return len(_DATA_ENTRY_RE.findall(text)) >= 2


def _iter_doc_files(root: Path):
    for path in iter_tree_or_filter(root):  # changed-file scope under --diff
        if not path.is_file():
            continue
        if any(d in EXCLUDE_DIRS for d in path.parts):
            continue
        if any(p.startswith(FROZEN_DIR_PREFIXES) for p in path.parts):
            continue
        if path.name.lower() in EXCLUDE_NAMES or EXCLUDE_NAME_RE.search(path.name):
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
            # utf-8-sig strips a leading BOM (a BOM'd capsule would otherwise carry
            # U+FEFF into the text); falls back to errors='replace' for non-UTF-8.
            text = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        if SKIP_MARKER in text:
            continue

        is_html = path.suffix.lower() in (".html", ".htm")
        # Interactive calculator apps are tools, not claim-bearing documents.
        if is_html and _is_interactive_tool(text):
            continue

        # A single locator anywhere clears the doc — conservative by design.
        # Checked against the FULL text (a DOI/URL in a script link still counts).
        if LOCATOR_RE.search(text):
            continue

        # For HTML, detect claims on the prose only — JS/CSS source is not a claim.
        scan_text = _strip_code_blocks(text) if is_html else text

        first_claim = None
        claim_hits = 0
        for pat in CLAIM_PATTERNS:
            for m in pat.finditer(scan_text):
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
