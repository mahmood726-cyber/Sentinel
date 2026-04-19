"""P0-baseline-drift: BLOCK when a shipped paper's numerical baseline
drifts beyond tolerance.

Activates only in repos that have adopted MissionCritical's baseline
corpus — i.e. `baseline.json` at the repo root. For each paper_id in
that corpus, looks for `<paper_id>.report.json` at the repo root; if
present, compares its numeric fields against the stored baseline. Any
field exceeding the configured tolerance (default 1e-6) is a BLOCK.

Silent no-op if:
  - `baseline.json` is absent (repo hasn't adopted MissionCritical).
  - `mission_critical` is not importable (dependency missing; user
    can install with `pip install mission-critical`).

Mission-critical severity: this rule encodes the "HR drifted from
0.80 to 0.81 between paper revisions, silently" failure class. See
MissionCritical README + research-integrity discussion.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P0-baseline-drift"
SEVERITY = Severity.BLOCK
SOURCE = "MissionCritical baseline corpus"
SCOPE = "repo"

DEFAULT_TOLERANCE = 1e-6


def _load_report(path: Path) -> dict[str, float] | None:
    """Return flat numeric dict from a report JSON. Returns None if
    unreadable. Unwraps diffmeta-shaped reports (pooled/python nest).
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    src = data.get("pooled") or data.get("python") or data
    if not isinstance(src, dict):
        return None
    # Rename log_or -> pooled_estimate for baseline store compatibility
    if "log_or" in src and "pooled_estimate" not in src:
        src = dict(src)
        src["pooled_estimate"] = src.pop("log_or")
    # Similarly, diffmeta's new unified name is "estimate"
    if "estimate" in src and "pooled_estimate" not in src:
        src = dict(src)
        src["pooled_estimate"] = src.pop("estimate")
    numeric: dict[str, float] = {}
    for k, v in src.items():
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)):
            numeric[k] = float(v)
    return numeric


def check(ctx: RepoContext) -> List[Verdict]:
    repo = ctx.repo_root
    baseline_path = repo / "baseline.json"
    if not baseline_path.is_file():
        return []

    now = datetime.now(timezone.utc)

    try:
        from mission_critical.baseline import BaselineStore
    except ImportError:
        return [Verdict(
            rule_id=ID,
            severity=Severity.WARN,  # WARN, not BLOCK — the user may
                                     # legitimately not have installed
                                     # MissionCritical yet.
            repo=str(repo),
            file="baseline.json",
            line=None,
            detail=(
                "baseline.json present but mission_critical package "
                "not installed; baseline drift cannot be checked"
            ),
            fix_hint=(
                "pip install mission-critical OR remove baseline.json "
                "if the MissionCritical workflow isn't in use"
            ),
            source=SOURCE,
            timestamp=now,
        )]

    try:
        store = BaselineStore(baseline_path)
    except RuntimeError as e:
        return [Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=str(repo),
            file="baseline.json",
            line=None,
            detail=f"baseline.json unreadable ({type(e).__name__})",
            fix_hint="repair baseline.json JSON structure",
            source=SOURCE,
            timestamp=now,
        )]

    verdicts: List[Verdict] = []
    for rec in store.all():
        report_path = repo / f"{rec.paper_id}.report.json"
        if not report_path.is_file():
            # No corresponding report — nothing to diff against this push.
            continue
        numeric = _load_report(report_path)
        if numeric is None:
            verdicts.append(Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(repo),
                file=f"{rec.paper_id}.report.json",
                line=None,
                detail=(
                    f"report for {rec.paper_id!r} exists but is not "
                    "readable/valid JSON"
                ),
                fix_hint=(
                    f"regenerate {rec.paper_id}.report.json or remove it"
                ),
                source=SOURCE,
                timestamp=now,
            ))
            continue
        try:
            diff_report = store.diff(
                rec.paper_id, numeric, tolerance=DEFAULT_TOLERANCE,
            )
        except KeyError:
            continue
        if not diff_report.exceeds_tolerance:
            continue
        preview_fields = sorted(diff_report.diffs.items())[:5]
        preview = "; ".join(
            f"{k}: {old:.6g} -> {new:.6g} (|d|={d:.2e})"
            for k, (old, new, d) in preview_fields
        )
        more = (
            f" (+{len(diff_report.diffs) - 5} more fields)"
            if len(diff_report.diffs) > 5 else ""
        )
        verdicts.append(Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=str(repo),
            file=f"{rec.paper_id}.report.json",
            line=None,
            detail=(
                f"numerical baseline drift for {rec.paper_id!r}: "
                f"max |diff| = {diff_report.max_abs_diff:.2e} "
                f"(tol {DEFAULT_TOLERANCE:.0e}). {preview}{more}"
            ),
            fix_hint=(
                f"investigate which input changed. If the drift is "
                f"legitimate (new studies, corrected input data), "
                f"rerun `baseline record {rec.paper_id} --from "
                f"{rec.paper_id}.report.json --overwrite` to update "
                f"the corpus"
            ),
            source=SOURCE,
            timestamp=now,
        ))

    return verdicts
