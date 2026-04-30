"""P1-cochrane-v65-invariants: WARN when a RapidMeta-style dashboard is
missing one of the Cochrane Handbook v6.5 / RevMan-2025 statistical
invariants that the engine portfolio standardised on at v13.0
(commit f415bff, 2026-04-29).

Rationale: a clone-script or hand-edit can easily produce a new
*_REVIEW.html that lacks REML, Q-profile, qchisq closed-form, ROB-ME, or
HKSJ floor. Without this rule, regressions appear silently in stat-card
output (e.g. tau2 CI saturating at 1e8 because qchisq(0.025, 1) returns 0
under Wilson-Hilferty).

Checks (each missing piece -> one WARN finding):
  1. REML iteration present (`tau2_reml` declared)
  2. REML primary, not DL (`const tau2_dl =` AND `const tau2 = (k >= 2) ? tau2_reml`)
  3. Q-profile tau2 CI helper (`qProfileTau2CI(`)
  4. qchisq closed-form for low df (`qchisq` AND `df === 1` near it)
  5. HKSJ floor (`Math.max(1, q*)` or `Math.max(1, qStar)`)
  6. PI df = k-1 (matches Cochrane v6.5; not k-2)
  7. ROB-ME framework (`_assessROBME(`)
  8. Mantel-Haenszel pool (`_mhPool(`)

WARN level (not BLOCK): these are quality drift signals; the dashboards
still function with degraded methods. Promote to BLOCK if a portfolio
sweep finds zero false positives.

Scope: *_REVIEW.html files that contain a `realData:` block (RapidMeta
shape). DTA *_DTA_REVIEW.html files use a different engine (loaded from
rapidmeta-dta-engine-v1.js) and have a separate set of invariants — they
are NOT checked by this rule.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import HTML_EXCLUDE_DIRS, iter_repo_files


ID = "P1-cochrane-v65-invariants"
SEVERITY = Severity.WARN
SOURCE = "advanced-stats.md#cochrane-v65-revman-2025-bit-reproducibility"
SCOPE = "repo"

MAX_FILE_BYTES = 10_000_000

# Each tuple: (substring or list of substrings, missing-detail, fix-hint)
# A check passes if ALL of the listed substrings appear in the file.
CHECKS: List[tuple] = [
    (
        ["tau2_reml"],
        "REML iteration block missing (no `tau2_reml` reference)",
        "run scripts/reml_primary_continuous.py and scripts/reml_primary_binary.py "
        "from the Finrenone repo, or hand-add the Newton-Raphson REML loop after "
        "the DL tau2 declaration",
    ),
    (
        ["const tau2_dl =", "const tau2 = (k >= 2) ? tau2_reml"],
        "REML is not primary (still using DL for sWR weights)",
        "rename the DL tau2 declaration to tau2_dl and add "
        "`const tau2 = (k >= 2) ? tau2_reml : tau2_dl;` after the REML iteration",
    ),
    (
        ["qProfileTau2CI"],
        "Q-profile tau2 CI helper missing (Cochrane v6.5 §10.10.4)",
        "run scripts/add_qprofile_tau2_ci.py from the Finrenone repo to insert the "
        "qchisq + qProfileTau2CI helpers near tQuantile",
    ),
    (
        ["qchisq", "df === 1"],
        "qchisq lacks df=1 closed-form -- Wilson-Hilferty saturates at small df",
        "run scripts/fix_qchisq_lowdf.py to add closed-forms for df=1 (z^2) and "
        "df=2 (-2*ln(1-p)); without this, k=2 dashboards return tau2 UCI = 1e8",
    ),
    (
        ["Math.max(1, qStar)"],
        "HKSJ floor `max(1, q*)` missing -- HKSJ CI may narrow below DL",
        "ensure the HKSJ adjustment uses `const hksjAdj = Math.max(1, qStar);` "
        "(advanced-stats.md HKSJ floor rule)",
    ),
    (
        ["// PI df = k-1 per Cochrane Handbook v6.5"],
        "Prediction interval still uses t_{k-2} (IntHout 2016) instead of "
        "t_{k-1} (Cochrane v6.5 §10.10.4.3 / RevMan-2025 default)",
        "run scripts/fix_pi_df_cochrane.py to flip k-2 -> k-1 and gate at k>=2",
    ),
    (
        ["_assessROBME("],
        "ROB-ME framework missing (Cochrane Ch.13 2024+)",
        "run scripts/add_robme_framework.py to add the chip-robme HTML element "
        "and the _assessROBME(c) method that produces the Q1-Q4 verdict",
    ),
    (
        ["_mhPool("],
        "Mantel-Haenszel pool missing (Cochrane v6.5 §10.4.1 sparse-binary "
        "preference)",
        "run scripts/add_mh_pool.py to add the _mhPool method with "
        "Robins-Breslow-Greenland variance and the sensitivity scenario push",
    ),
]


def _line_of_first_match(text: str, needles: List[str]) -> int:
    """Return the line number of the first `needles` substring found,
    or 1 if none match."""
    for needle in needles:
        idx = text.find(needle)
        if idx >= 0:
            return text.count('\n', 0, idx) + 1
    return 1


def _check_one_file(text: str, rel: str, now: datetime) -> List[Verdict]:
    verdicts: List[Verdict] = []
    # Only flag dashboards that have the RapidMeta shape (realData: { ... }).
    # Skip DTA dashboards (different engine).
    if 'realData:' not in text and 'realData =' not in text:
        return verdicts
    if rel.endswith('_DTA_REVIEW.html'):
        return verdicts
    # Skip frozen submission snapshots — those are intentionally pinned to
    # the version that was reviewed and should not be re-aligned mid-review.
    if 'e156-submission/' in rel or '/snapshots/' in rel or '.bak.html' in rel:
        return verdicts

    for needles, detail, fix_hint in CHECKS:
        if all(n in text for n in needles):
            continue
        # Report at line 1 (file-level finding) or at the line of a related
        # token if we can find one.
        line = 1
        related = ['ContinuousMDEngine', 'AnalysisEngine', 'realData:', 'updateStatCards']
        for r in related:
            idx = text.find(r)
            if idx >= 0:
                line = text.count('\n', 0, idx) + 1
                break
        verdicts.append(Verdict(
            rule_id=ID,
            severity=Severity.WARN,
            repo=None,
            file=rel,
            line=line,
            detail=detail,
            fix_hint=fix_hint,
            source=SOURCE,
            timestamp=now,
        ))

    return verdicts


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []

    for path in _iter_html_files(ctx.repo_root):
        rel = path.relative_to(ctx.repo_root).as_posix()
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for v in _check_one_file(text, rel, now):
            verdicts.append(Verdict(
                rule_id=v.rule_id,
                severity=v.severity,
                repo=str(ctx.repo_root),
                file=v.file,
                line=v.line,
                detail=v.detail,
                fix_hint=v.fix_hint,
                source=v.source,
                timestamp=v.timestamp,
            ))

    return verdicts


def _iter_html_files(root: Path) -> Iterator[Path]:
    for path in iter_repo_files(root, '*_REVIEW.html', HTML_EXCLUDE_DIRS):
        yield path
