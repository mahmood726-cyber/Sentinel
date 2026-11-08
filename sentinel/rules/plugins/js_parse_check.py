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
from sentinel.io.git_files import GitFileEnumerationError, JS_EXCLUDE_DIRS, iter_repo_files
from sentinel.io.population import Population
from sentinel.io.skip_marker import has_skip_marker


ID = "P1-js-parse-check"
SEVERITY = Severity.BLOCK
SOURCE = "lessons.md#code-quality"
SCOPE = "repo"

# Population: PRESENT -- tracked AND untracked-not-ignored. This is a
# CORRECTNESS rule: the defect it finds runs when someone runs the file,
# whether or not git is tracking it. Migrated 2026-08-30; counts from
# before that date were taken over the tracked set only and are NOT
# comparable with counts after it.
POPULATION = Population.PRESENT

EXTENSION_PATTERNS = ("*.js", "*.mjs", "*.cjs")

# A timeout aborts the scan even in warn mode, so it has to mean "node cannot
# answer", not "this host is slow". `node --check` has been recorded taking
# over 10s on Windows. One retry absorbs a transient stall; a second timeout
# stays closed.
NODE_TIMEOUT_SECONDS = 60
NODE_ATTEMPTS = 2


def check(ctx: RepoContext) -> List[Verdict]:
    # Determine availability once, but only fail if there is a real,
    # non-excluded JS candidate to inspect. Pure Python repos remain clean.
    node_available = shutil.which("node") is not None

    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    repo_prefix = str(ctx.repo_root)

    for path in _iter_js_files(ctx.repo_root):
        rel = path.relative_to(ctx.repo_root).as_posix()
        if has_skip_marker(path):
            continue
        if not node_available:
            # Returning [] here used to report a clean push despite an
            # uninspected JS BLOCK candidate. Warn-mode hooks may permit
            # ordinary BLOCK verdicts, so use the fatal scanner contract.
            raise GitFileEnumerationError(
                "JavaScript parse scan cannot run (node unavailable)"
            )
        # Defense-in-depth: make sure the path can't be interpreted as
        # an option by node. iter_repo_files yields absolute paths
        # already, which on every supported platform start with "/" or
        # "<drive>:", neither of which node treats as an option. The
        # guard below is belt-and-braces for future refactors.
        path_arg = str(path)
        if path_arg.startswith("-"):
            path_arg = f"./{path_arg}"

        result = _node_check(path_arg)

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


def _node_check(path_arg: str) -> subprocess.CompletedProcess:
    for attempt in range(1, NODE_ATTEMPTS + 1):
        try:
            return subprocess.run(
                ["node", "--check", path_arg],
                capture_output=True, text=True, timeout=NODE_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            if attempt < NODE_ATTEMPTS:
                continue
            failure = exc
        except (OSError, UnicodeError) as exc:
            failure = exc
        # Timeout, missing executable and undecodable parser output mean
        # the candidate was never conclusively inspected. Never turn
        # this into an ordinary, warn-downgradable BLOCK finding.
        # Suppress the OS/process exception chain (private paths).
        raise GitFileEnumerationError(
            f"JavaScript parse candidate not inspected ({type(failure).__name__})"
        ) from None
    raise AssertionError("unreachable: every attempt returns or raises")


def _iter_js_files(root: Path):
    # Single git ls-files call for all three extensions — avoids 3x
    # subprocess overhead per scan (see review-findings.md#P1-5).
    for path in iter_repo_files(root, EXTENSION_PATTERNS, JS_EXCLUDE_DIRS, population=POPULATION):
        if path.name.endswith(".min.js"):
            continue
        yield path
