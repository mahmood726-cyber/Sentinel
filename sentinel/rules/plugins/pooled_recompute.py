"""P1-pooled-recompute: WARN when a review's stated pooled estimate is
incompatible with an independent re-pool of its own per-trial data.

E156 Assurance Standard "Analysis errors" risk class (check #3, the standard's
"if the paper says OR 0.78 but the rerun gives 0.87 it fails"). The companion
rule `dashboard_match` only checks the body claim sits within the per-trial
min/max range +/-0.2 — a wrong-model, sign-flipped, or transcription-error
pooled estimate that happens to land inside that loose range passes clean.

This rule actually RE-POOLS. From each trial's published HR and 95% CI it
recovers logHR and its SE (on the log scale, per the Cochrane Handbook), then
computes both the inverse-variance fixed-effect and the DerSimonian-Laird
random-effects pooled HR, and compares the body's stated pooled HR to that.

Two tiers, both FP-disciplined (2026-05-28 portfolio FP audit):
  - DIRECTION contradiction: body claim and re-pool sit on opposite sides of
    1.0 (each clear of the null by >5%). An unambiguous sign error. WARN by
    default; BLOCK with SENTINEL_POOLED_RECOMPUTE_BLOCK=1.
  - MAGNITUDE mismatch: body claim outside the [fixed, random] range widened
    by +/-15%. The 15% cushion is deliberately generous so legitimate method
    differences (DL vs REML vs HKSJ point estimates differ by ~1-3%) never
    fire — only gross errors do. Always WARN.

Fires only on *_REVIEW.html with >=2 trials carrying HR + both CI bounds and a
single body-level pooled claim; honors sentinel:skip-file. The DL estimator is
used only to bound a plausibility range (not as a published estimate), so the
small-k DL bias caveat does not apply to this consistency check.
"""
from __future__ import annotations

import math
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.rules.plugins.dashboard_match import (
    POOLED_BODY_RE,
    _iter_target_files,
    _per_trial_hrs,
    _strip_scripts,
)
from sentinel.rules.plugins.denominator_logic import _line_of


ID = "P1-pooled-recompute"
SEVERITY = Severity.WARN
SOURCE = "F:\\e156\\docs\\assurance-standard.md#3-analysis-checking"
SCOPE = "repo"

MAX_FILE_BYTES = 10_000_000
SKIP_MARKER = "sentinel:skip-file"
Z_975 = 1.959963984540054      # qnorm(0.975)
WIDEN = 0.15                   # +/-15% cushion absorbs RE-method point differences
NULL_MARGIN = 0.05             # how far from HR=1 a claim must be to count as "directional"

_BLOCK_OPT_IN = os.environ.get("SENTINEL_POOLED_RECOMPUTE_BLOCK") == "1"

# Looser prose matcher so an author cannot evade the re-pool merely by wording
# ("the hazard ratio was 0.65 (95% CI ...)", "HR of 0.65 (95% CI ...)"). FP is
# controlled by requiring the CI in parentheses immediately after the estimate
# and forbidding intervening digits between the measure and the value.
POOLED_BODY_PROSE_RE = re.compile(
    r"\b(OR|HR|RR|IRR|hazard ratio|odds ratio|risk ratio|rate ratio|incidence rate ratio)\b"
    r"[^\d\n]{0,20}?(\d+\.\d+)\s*"
    r"[\(\[]\s*(?:95\s*%?\s*C[rI]I?\s*:?\s*)?(\d+\.\d+)\s*[-–to]+\s*(\d+\.\d+)",
    re.IGNORECASE,
)


def pool_hr_ci(trials: List[Tuple[str, float, float, float]]) -> Optional[Tuple[float, float, int]]:
    """Re-pool per-trial (nct, hr, lci, uci) into (fixed_hr, random_hr, k).

    Inverse-variance on the log scale; DerSimonian-Laird tau^2 for the
    random-effects weights. Returns None if fewer than 2 usable trials.
    """
    logs: List[float] = []
    var: List[float] = []
    for _nct, hr, lci, uci in trials:
        if hr <= 0 or lci <= 0 or uci <= 0:
            continue
        if not (lci <= hr <= uci):
            continue  # impossible CI — denominator_logic owns that BLOCK
        se = (math.log(uci) - math.log(lci)) / (2.0 * Z_975)
        if se <= 0:
            continue
        logs.append(math.log(hr))
        var.append(se * se)
    k = len(logs)
    if k < 2:
        return None

    w = [1.0 / v for v in var]
    sw = sum(w)
    fe = sum(wi * li for wi, li in zip(w, logs)) / sw

    q = sum(wi * (li - fe) ** 2 for wi, li in zip(w, logs))
    df = k - 1
    c = sw - sum(wi * wi for wi in w) / sw
    tau2 = max(0.0, (q - df) / c) if c > 0 else 0.0

    wr = [1.0 / (v + tau2) for v in var]
    swr = sum(wr)
    re = sum(wi * li for wi, li in zip(wr, logs)) / swr

    return (math.exp(fe), math.exp(re), k)


def _check_one_file(text: str, rel: str, now: datetime) -> List[Verdict]:
    trials = _per_trial_hrs(text)
    if len(trials) < 2:
        return []
    pooled = pool_hr_ci(trials)
    if pooled is None:
        return []
    fe, re, k = pooled

    body = _strip_scripts(text)
    bm = POOLED_BODY_RE.search(body) or POOLED_BODY_PROSE_RE.search(body)
    if not bm:
        return []
    try:
        body_hr = float(bm.group(2))
    except (TypeError, ValueError):
        return []
    measure = bm.group(1).upper()

    lo = min(fe, re) * (1.0 - WIDEN)
    hi = max(fe, re) * (1.0 + WIDEN)
    line = _line_of(text, text.find(bm.group(0)) if bm.group(0) in text else 0)

    # Direction contradiction — body and re-pool on opposite sides of the null.
    directional = (
        abs(body_hr - 1.0) > NULL_MARGIN
        and abs(re - 1.0) > NULL_MARGIN
        and (body_hr - 1.0) * (re - 1.0) < 0
    )
    if directional:
        sev = Severity.BLOCK if _BLOCK_OPT_IN else Severity.WARN
        return [Verdict(
            rule_id=ID,
            severity=sev,
            repo=None,
            file=rel,
            line=line,
            detail=(
                f"stated pooled {measure} {body_hr} points the OPPOSITE way to a "
                f"re-pool of this review's own {k} trials (fixed {fe:.2f} / "
                f"random {re:.2f}) — likely a sign/direction error or "
                f"treatment/control swap"
            ),
            fix_hint=(
                "re-check the effect direction and which arm is treatment; pool "
                "logHR and back-transform. If the body reports a different "
                "outcome than the per-trial data, label it so it isn't read as "
                "the primary pooled estimate"
            ),
            source=SOURCE,
            timestamp=now,
        )]

    # Magnitude mismatch — same direction but well outside the plausible range.
    if body_hr < lo or body_hr > hi:
        return [Verdict(
            rule_id=ID,
            severity=Severity.WARN,
            repo=None,
            file=rel,
            line=line,
            detail=(
                f"stated pooled {measure} {body_hr} is outside a re-pool of this "
                f"review's own {k} trials (fixed {fe:.2f} / random {re:.2f}; "
                f"plausible {lo:.2f}-{hi:.2f}) — verify the model and inputs"
            ),
            fix_hint=(
                "regenerate the pooled estimate from the current per-trial data "
                "(inverse-variance on logHR); confirm fixed vs random-effects "
                "choice matches what the body claims"
            ),
            source=SOURCE,
            timestamp=now,
        )]

    return []


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
        if SKIP_MARKER in text:
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
