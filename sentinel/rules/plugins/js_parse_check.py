"""P1-js-parse-check: BLOCK pushes containing JS files that fail node's parser.

Catches syntax errors (unbalanced parens, missing semicolons, stray tokens)
before they reach a "submission-ready" state.

Background: 2026-04-15 maicSTC.js incident. A new MAIC engine shipped with a
missing closing paren on line 100. The full Jest suite for that engine failed
to LOAD (0/35 tests runnable). No CI, no local git, no test gate caught it
because the file never reached a push hook.

This rule closes the syntactic-failure gap. Logic regressions remain CI's job.

Cost: ~10ms per file. On a 200-file repo this adds ~2 seconds to pre-push,
within Sentinel's sub-5-second budget.

TypeScript: deliberately skipped. `node --check` rejects TS-specific syntax
(type annotations, `interface`, etc.) and would false-positive on any typed
file. A future TS-parse rule should shell out to `tsc --noEmit` instead.
"""
from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P1-js-parse-check"
SEVERITY = Severity.BLOCK
SOURCE = "lessons.md#code-quality"
SCOPE = "repo"

EXTENSIONS = {".js", ".mjs", ".cjs"}
EXCLUDE_DIRS = {
    "node_modules", "dist", "build", "vendor", "coverage", ".git",
    ".pytest_cache", "__pycache__", "playwright-report", "test-results",
}


def check(ctx: RepoContext) -> List[Verdict]:
    if shutil.which("node") is None:
        return []

    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []

    for path in _iter_js_files(ctx.repo_root):
        rel = path.relative_to(ctx.repo_root).as_posix()
        try:
            result = subprocess.run(
                ["node", "--check", str(path)],
                capture_output=True, text=True, timeout=10,
            )
        except subprocess.TimeoutExpired:
            verdicts.append(Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(ctx.repo_root),
                file=rel,
                line=None,
                detail="node --check timed out after 10s",
                fix_hint=f"investigate why parsing {rel} is slow",
                source=SOURCE,
                timestamp=now,
            ))
            continue

        if result.returncode != 0:
            stderr_lines = (result.stderr or "").strip().splitlines()
            detail = stderr_lines[0] if stderr_lines else "node --check failed"
            verdicts.append(Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(ctx.repo_root),
                file=rel,
                line=None,
                detail=detail[:200],
                fix_hint=f"run `node --check {rel}` locally and fix the syntax error",
                source=SOURCE,
                timestamp=now,
            ))

    return verdicts


def _iter_js_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in EXTENSIONS:
            continue
        if path.name.endswith(".min.js"):
            continue
        if any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        yield path
