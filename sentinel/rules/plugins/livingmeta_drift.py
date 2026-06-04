"""P0-livingmeta-drift: wraps audit_livingmeta_claims.py as a portfolio rule.

Exit contract (per audit_livingmeta_claims.py:345):
  0  -> no drift; silent.
  2  -> drift found; BLOCK with summary.
  *  -> script error; BLOCK with stderr excerpt.
"""
from __future__ import annotations
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P0-livingmeta-drift"
SEVERITY = Severity.BLOCK
SOURCE = "projectindex-audit.md"
SCOPE = "portfolio"

TIMEOUT_SECONDS = 300
SCRIPT_NAME = "audit_livingmeta_claims.py"


def check(ctx: RepoContext) -> List[Verdict]:
    pi_root = ctx.project_index_root
    assert pi_root is not None, "portfolio scope guarantees project_index_root"
    now = datetime.now(timezone.utc)

    script = pi_root / SCRIPT_NAME
    if not script.is_file():
        return [
            Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(pi_root),
                file=None,
                line=None,
                detail=f"{SCRIPT_NAME} not found at {script}",
                fix_hint=f"restore {SCRIPT_NAME} in the configured project index",
                source=SOURCE,
                timestamp=now,
            )
        ]

    try:
        result = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=TIMEOUT_SECONDS,
            cwd=str(pi_root),
        )
    except subprocess.TimeoutExpired:
        return [
            Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(pi_root),
                file=str(script),
                line=None,
                detail=f"{SCRIPT_NAME} exceeded {TIMEOUT_SECONDS}s - killed",
                fix_hint="investigate why the audit hangs; do not raise timeout blindly",
                source=SOURCE,
                timestamp=now,
            )
        ]

    if result.returncode == 0:
        return []

    combined = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
    excerpt = combined[-600:] if len(combined) > 600 else combined

    if result.returncode == 2:
        detail = f"LivingMeta claim-drift detected: {excerpt}"
        hint = (
            "run `python <project-index>/diagnose_drift.py <project>` to inspect "
            "the drifting project, then repair workbook or HTML before pushing"
        )
    else:
        detail = f"{SCRIPT_NAME} exited {result.returncode}: {excerpt}"
        hint = f"fix the audit script crash (not a drift verdict); exit code was {result.returncode}"

    return [
        Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=str(pi_root),
            file=str(script),
            line=None,
            detail=detail,
            fix_hint=hint,
            source=SOURCE,
            timestamp=now,
        )
    ]
