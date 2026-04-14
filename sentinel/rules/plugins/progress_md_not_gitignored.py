"""P2-progress-md-not-gitignored: INFO if PROGRESS.md is tracked by git.

PROGRESS.md is a per-session handoff artifact that may contain local paths
or internal state — CLAUDE.md#session-recovery requires it to be
gitignored. This rule is INFO tier: surfaced on dashboards, not
push-blocking."""
from __future__ import annotations
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P2-progress-md-not-gitignored"
SEVERITY = Severity.INFO
SOURCE = "workflow.md#savepoint-discipline"
SCOPE = "repo"


def check(ctx: RepoContext) -> List[Verdict]:
    progress = ctx.repo_root / "PROGRESS.md"
    if not progress.is_file():
        return []
    try:
        result = subprocess.run(
            ["git", "check-ignore", "PROGRESS.md"],
            cwd=str(ctx.repo_root),
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    # git check-ignore exit 0 = ignored, 1 = NOT ignored, 128 = error
    if result.returncode == 0:
        return []  # properly gitignored
    if result.returncode != 1:
        return []  # error (not a git repo, etc.) — fail open for INFO

    return [
        Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=str(ctx.repo_root),
            file="PROGRESS.md",
            line=None,
            detail="PROGRESS.md is tracked by git; may contain local paths or session state",
            fix_hint="Add PROGRESS.md to .gitignore.",
            source=SOURCE,
            timestamp=datetime.now(timezone.utc),
        )
    ]
