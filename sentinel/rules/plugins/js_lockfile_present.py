"""P1-js-lockfile-present: WARN when package.json has no companion lockfile.

A repo with package.json but no package-lock.json / yarn.lock / pnpm-lock.yaml
/ bun.lockb is a reproducibility risk — `npm install` in a fresh clone can
resolve to different transitive dependency versions than the ones the tests
ran against.

Triggering incident: HTA Artifact shipped to GitHub without
package-lock.json for ~4 weeks. package.json declared npm scripts
(quality:gate etc.) but the dependency tree those scripts ran against
was unpinned for fresh cloners.

Severity: WARN (not BLOCK) because adding a lockfile is a one-command
fix (`npm install`) and the miss doesn't break correctness — it erodes
reproducibility guarantees.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P1-js-lockfile-present"
SEVERITY = Severity.WARN
SOURCE = "lessons.md#code-quality"
SCOPE = "repo"

LOCKFILES = (
    "package-lock.json",  # npm
    "yarn.lock",          # yarn
    "pnpm-lock.yaml",     # pnpm
    "bun.lockb",          # bun
)


def check(ctx: RepoContext) -> List[Verdict]:
    pkg = ctx.repo_root / "package.json"
    if not pkg.is_file():
        return []

    if any((ctx.repo_root / name).is_file() for name in LOCKFILES):
        return []

    return [Verdict(
        rule_id=ID,
        severity=SEVERITY,
        repo=str(ctx.repo_root),
        file="package.json",
        line=None,
        detail=(
            "package.json present but no lockfile found "
            f"({', '.join(LOCKFILES)}). Fresh clones will resolve unpinned "
            "dependency versions."
        ),
        fix_hint=(
            "run `npm install` (or `yarn`, `pnpm install`, `bun install`) "
            "once locally and commit the generated lockfile"
        ),
        source=SOURCE,
        timestamp=datetime.now(timezone.utc),
    )]
