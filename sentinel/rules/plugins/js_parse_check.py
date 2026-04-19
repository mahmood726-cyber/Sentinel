"""P1-js-parse-check: BLOCK pushes containing JS files that fail node's parser.

Catches syntax errors (unbalanced parens, missing semicolons, stray tokens)
before they reach a "submission-ready" state.

Background: 2026-04-15 maicSTC.js incident. A new MAIC engine shipped
with a missing closing paren on line 100. The full Jest suite for that
engine failed to LOAD (0/35 tests runnable). No CI, no local git, no
test gate caught it because the file never reached a push hook.

This rule closes the syntactic-failure gap. Logic regressions remain
CI's job.

Cost: ~10ms per file (single git subprocess + one node --check per
matching file). 200-file JS repo adds ~2 seconds to pre-push.

TypeScript: deliberately skipped. `node --check` rejects TS-specific
syntax (type annotations, `interface`, etc.) and would false-positive
on any typed file. A future TS-parse rule should shell out to `tsc
--noEmit` instead.
"""
from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import JS_EXCLUDE_DIRS, iter_repo_files


ID = "P1-js-parse-check"
SEVERITY = Severity.BLOCK
SOURCE = "lessons.md#code-quality"
SCOPE = "repo"

EXTENSION_PATTERNS = ("*.js", "*.mjs", "*.cjs")


def check(ctx: RepoContext) -> List[Verdict]:
    if shutil.which("node") is None:
        return []

    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    repo_prefix = str(ctx.repo_root)

    for path in _iter_js_files(ctx.repo_root):
        rel = path.relative_to(ctx.repo_root).as_posix()
        # Defense-in-depth: make sure the path can't be interpreted as
        # an option by node. iter_repo_files yields absolute paths
        # already, which on every supported platform start with "/" or
        # "<drive>:", neither of which node treats as an option. The
        # guard below is belt-and-braces for future refactors.
        path_arg = str(path)
        if path_arg.startswith("-"):
            path_arg = f"./{path_arg}"

        try:
            result = subprocess.run(
                ["node", "--check", path_arg],
                capture_output=True, text=True, timeout=10,
            )
        except subprocess.TimeoutExpired:
            verdicts.append(Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=repo_prefix,
                file=rel,
                line=None,
                detail="node --check exceeded 10s",
                fix_hint=(
                    f"parsing {rel} exceeded 10s — check for a pathological "
                    f"regex or huge literal; reproduce with "
                    f"`node --check {rel}` locally"
                ),
                source=SOURCE,
                timestamp=now,
            ))
            continue

        if result.returncode != 0:
            stderr = (result.stderr or "").replace(repo_prefix, "")
            stderr_lines = stderr.strip().splitlines()
            detail = stderr_lines[0] if stderr_lines else "node --check failed"
            verdicts.append(Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=repo_prefix,
                file=rel,
                line=None,
                detail=detail[:200],
                fix_hint=f"run `node --check {rel}` locally and fix the syntax error",
                source=SOURCE,
                timestamp=now,
            ))

    return verdicts


def _iter_js_files(root: Path):
    # Single git ls-files call for all three extensions — avoids 3x
    # subprocess overhead per scan (see review-findings.md#P1-5).
    for path in iter_repo_files(root, EXTENSION_PATTERNS, JS_EXCLUDE_DIRS):
        if path.name.endswith(".min.js"):
            continue
        yield path
