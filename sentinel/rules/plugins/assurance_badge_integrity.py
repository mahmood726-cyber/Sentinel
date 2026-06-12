"""P1-assurance-badge-integrity: WARN when an assurance.json claims a tier its
own checks don't support (a forged or stale badge).

E156 Assurance Standard self-consistency — "the capsule must agree with itself".
The badge is supposed to be DERIVED from check verdicts by
build_assurance_jsons.compute_tier. A hand-edited assurance.json that asserts
`"tier": "gold"` while its checks don't earn it is exactly the forgery the
standard exists to prevent (2026-05-28 red-team #5).

This rule recomputes the tier from the file's own `checks` block and flags any
disagreement, plus malformed badges (bad JSON, missing tier/checks).

Tier logic is duplicated here from build_assurance_jsons.compute_tier so the
rule stays self-contained; a contract test in the E156 repo
(test_assurance_badge.py::test_badge_integrity_rule_matches_compute_tier)
asserts the two stay identical.

FP discipline (2026-05-28 portfolio FP audit): build-generated badges are
self-consistent by construction, so this rule is inert on them. It only fires
on hand-edited or malformed badges. Default severity is WARN (the deferred
portfolio regen may leave a few stale badges); set
SENTINEL_ASSURANCE_BADGE_BLOCK=1 to promote to BLOCK once badges are regenerated.
Honors sentinel:skip-file.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import path_allowed


ID = "P1-assurance-badge-integrity"
SEVERITY = Severity.WARN
SOURCE = "F:\\e156\\docs\\assurance-standard.md#the-assurancejson-schema"
SCOPE = "repo"

SKIP_MARKER = "sentinel:skip-file"
BADGE_NAME = "assurance.json"
MAX_FILE_BYTES = 1_000_000
EXCLUDE_DIRS = frozenset((
    "node_modules", "__pycache__", ".git", ".pytest_cache", ".venv",
    "venv", "build", "dist", ".tox", ".mypy_cache",
))
_VALID_TIERS = frozenset(("none", "bronze", "silver", "gold"))
_BLOCK_OPT_IN = os.environ.get("SENTINEL_ASSURANCE_BADGE_BLOCK") == "1"

_PASS_OR_NOT_RUN = ("pass", "not-run")


def compute_tier(checks: dict) -> str:
    """MUST stay identical to build_assurance_jsons.compute_tier."""
    if "fail" in checks.values():
        return "none"
    bronze_ok = (
        checks.get("citation_cascade") != "fail"
        and checks.get("data_file_present") == "pass"
        and checks.get("code_runs") in _PASS_OR_NOT_RUN
    )
    if not bronze_ok:
        return "none"
    silver_ok = (
        checks.get("dashboard_match") == "pass"
        and checks.get("claim_language") == "pass"
        and checks.get("publication_bias", "not-run") in _PASS_OR_NOT_RUN
    )
    if not silver_ok:
        return "bronze"
    gold_ok = (
        checks.get("analysis_rerun") == "pass"
        and checks.get("external_review") == "pass"
    )
    return "gold" if gold_ok else "silver"


def _severity() -> Severity:
    return Severity.BLOCK if _BLOCK_OPT_IN else Severity.WARN


def _iter_badges(root: Path):
    for p in root.rglob(BADGE_NAME):
        if not path_allowed(root, p):
            continue  # honor `scan --diff` changed-file scope
        if any(d in EXCLUDE_DIRS for d in p.parts):
            continue
        if p.is_file():
            yield p


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    root = ctx.repo_root
    verdicts: List[Verdict] = []
    for path in _iter_badges(root):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if SKIP_MARKER in text:
            continue
        rel = path.relative_to(root).as_posix()

        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            verdicts.append(Verdict(
                rule_id=ID, severity=_severity(), repo=str(root), file=rel, line=1,
                detail=f"assurance.json is not valid JSON: {e}",
                fix_hint="regenerate it with scripts/build_assurance_jsons.py",
                source=SOURCE, timestamp=now,
            ))
            continue
        if not isinstance(data, dict):
            continue

        checks = data.get("checks")
        stored = data.get("tier")
        if not isinstance(checks, dict) or stored is None:
            verdicts.append(Verdict(
                rule_id=ID, severity=_severity(), repo=str(root), file=rel, line=1,
                detail="assurance.json is missing a 'checks' object or 'tier' field",
                fix_hint="regenerate it with scripts/build_assurance_jsons.py",
                source=SOURCE, timestamp=now,
            ))
            continue
        if stored not in _VALID_TIERS:
            verdicts.append(Verdict(
                rule_id=ID, severity=_severity(), repo=str(root), file=rel, line=1,
                detail=f"assurance.json tier {stored!r} is not one of {sorted(_VALID_TIERS)}",
                fix_hint="regenerate it with scripts/build_assurance_jsons.py",
                source=SOURCE, timestamp=now,
            ))
            continue

        recomputed = compute_tier(checks)
        if recomputed != stored:
            verdicts.append(Verdict(
                rule_id=ID, severity=_severity(), repo=str(root), file=rel, line=1,
                detail=(
                    f"assurance.json claims tier {stored!r} but its own checks "
                    f"compute to {recomputed!r} — forged or stale badge. The badge "
                    f"must be derived from the checks, not asserted."
                ),
                fix_hint=(
                    "regenerate with scripts/build_assurance_jsons.py; never "
                    "hand-edit the tier. Honest under-claiming is the safer error."
                ),
                source=SOURCE, timestamp=now,
            ))
    return verdicts
