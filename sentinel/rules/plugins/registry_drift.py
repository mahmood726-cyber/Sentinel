"""P0-registry-drift: wraps reconcile_counts.py as a portfolio-scoped rule."""
from __future__ import annotations
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P0-registry-drift"
SEVERITY = Severity.BLOCK
SOURCE = "workflow.md#registry-reconciliation-gate"
SCOPE = "portfolio"

TIMEOUT_SECONDS = 120


def check(ctx: RepoContext) -> List[Verdict]:
    pi_root = ctx.project_index_root
    assert pi_root is not None, "portfolio scope guarantees project_index_root"
    now = datetime.now(timezone.utc)

    script = pi_root / "reconcile_counts.py"
    if not script.is_file():
        return [
            Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(pi_root),
                file=None,
                line=None,
                detail=f"reconcile_counts.py not found at {script}",
                fix_hint="restore reconcile_counts.py in C:/ProjectIndex/",
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
                detail=f"reconcile_counts.py exceeded {TIMEOUT_SECONDS}s — killed",
                fix_hint="investigate why reconcile hangs; do not raise timeout blindly",
                source=SOURCE,
                timestamp=now,
            )
        ]

    if result.returncode == 0:
        return []

    combined = (result.stdout or "") + "\n" + (result.stderr or "")
    return [
        Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=str(pi_root),
            file=str(script),
            line=None,
            detail=f"reconcile_counts.py exited {result.returncode}: {combined.strip()[:400]}",
            fix_hint="resolve INDEX.md / manifest / workbook drift before any portfolio action",
            source=SOURCE,
            timestamp=now,
        )
    ]
