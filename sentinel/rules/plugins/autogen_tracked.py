"""P2-autogen-tracked: WARN when known auto-generated files are tracked in git.

Triggering incidents (2026-04-16 portfolio audit):
  - shifaa, overmind tracked review-findings.md (Sentinel's pre-rename
    WARN output filename) — 16 + 4384 lines of stale auto-content in git
    history, reappearing as diff noise on every scan that wrote the old
    filename.
  - overmind also tracked data/nightly_reports/latest.json (523-line
    delta on every nightly) + nightly.log + data/stability_state.json
    (356-line delta) — 5,431 lines of pure autogen noise in git status.

Covered filenames (by basename match):
  - PROGRESS.md, DECISIONS.md        (session / Overmind logs)
  - STUCK_FAILURES.md/.jsonl         (Sentinel BLOCK output)
  - sentinel-findings.md/.jsonl      (Sentinel WARN output, post-rename)
  - review-findings.md/.jsonl        (Sentinel WARN output, pre-rename)
  - stability_state.json             (Overmind nightly stability)
  - latest.json under nightly_reports (Overmind nightly snapshot)

Fix: `git rm --cached <file>` (keeps the file on disk, drops from index)
+ add the filename to .gitignore so it stays out.

Severity: WARN (not BLOCK). Tracking an autogen file isn't a correctness
or security issue; it's diff hygiene. A nudge, not a gate.

Generalization of P2-progress-md-not-gitignored (2026-04-15) to the broader
autogen family. That rule ships alongside and can be retired in a future
sweep once this one has been in production long enough to prove coverage.
"""
from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Set

from sentinel.core import RepoContext, Severity, Verdict


ID = "P2-autogen-tracked"
SEVERITY = Severity.WARN
SOURCE = "lessons.md#portfolio-audit-patterns"
SCOPE = "repo"

# Basenames of files that should never be tracked (auto-generated)
AUTOGEN_BASENAMES: Set[str] = {
    "PROGRESS.md",
    "DECISIONS.md",
    "STUCK_FAILURES.md",
    "STUCK_FAILURES.jsonl",
    "sentinel-findings.md",
    "sentinel-findings.jsonl",
    "review-findings.md",
    "review-findings.jsonl",
    "stability_state.json",
}

# Path patterns (match if basename matches AND path contains pattern)
# Tuples: (basename, path-contains-requirement)
AUTOGEN_PATH_PATTERNS = [
    ("latest.json", "nightly_reports"),  # data/nightly_reports/latest.json
]


def check(ctx: RepoContext) -> List[Verdict]:
    repo = ctx.repo_root
    if not (repo / ".git").is_dir():
        return []

    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "ls-files"],
            capture_output=True, text=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    if result.returncode != 0:
        return []

    tracked = [line for line in result.stdout.splitlines() if line]
    if not tracked:
        return []

    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []

    for path in tracked:
        basename = path.rsplit("/", 1)[-1]
        matched = False

        if basename in AUTOGEN_BASENAMES:
            matched = True
        else:
            for needle_name, needle_path in AUTOGEN_PATH_PATTERNS:
                if basename == needle_name and needle_path in path:
                    matched = True
                    break

        if matched:
            verdicts.append(Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(repo),
                file=path,
                line=None,
                detail=f"{path} is auto-generated but tracked in git",
                fix_hint=(
                    f"`git rm --cached {path}` + append `{basename}` "
                    "to .gitignore"
                ),
                source=SOURCE,
                timestamp=now,
            ))

    return verdicts
