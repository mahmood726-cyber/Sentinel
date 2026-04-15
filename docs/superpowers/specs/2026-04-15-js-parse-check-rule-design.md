# Spec: P1-js-parse-check rule

Status: design-only; not implemented.
Date: 2026-04-15
Triggering incident: HTA Artifact `src/engine/maicSTC.js:100` shipped with a
missing closing paren. Jest suite failed to LOAD (0/35 tests runnable). Cause:
no git tracking on `C:\HTML apps\HTA\` at the time, so pre-push hooks could
not fire; no CI; no local test-run discipline before the engine was added.

## Goal

Block pushes that introduce JS/TS files with syntax errors, so incidents like
maicSTC.js cannot reach a "submission-ready" state undetected.

## Non-goals

- Catching logic regressions (that's Jest's job, run in CI or explicit
  `npm test`).
- Catching runtime errors (same).
- Running the full test suite pre-push (speed budget — see below).

## Design alternatives considered

| # | What runs pre-push | Cost | Catches maicSTC bug | Catches logic regressions |
|---|---|---|---|---|
| 1 | `node --check` on staged `.js/.ts/.mjs` | ~10ms/file | yes | no |
| 2 | `npx jest --onlyChanged` | seconds–minutes | yes | yes for covered code |
| 3 | `node -e "require('./<file>')"` | ~100ms/file | yes | partial (import errors only) |

## Recommended: Option 1 (parse-only)

Rationale:
- The speed budget for pre-push hooks is ~5 seconds before humans start
  bypassing them. Sentinel's existing 11 rules are all sub-second (pattern
  match or light Python). Option 2 would cross that threshold and erode the
  no-bypass norm tracked in `~/.sentinel-logs/bypass.log`.
- The incident this rule is responding to is a SYNTAX error. A parse-check is
  the exact-match gate.
- Option 1 works on any JS repo without needing Jest configured. Broader
  applicability = more repos covered.
- Logic regressions belong in CI, not pre-push.

## Implementation sketch

File: `C:\Sentinel\sentinel\rules\plugins\js_parse_check.py`

```python
from __future__ import annotations
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict

ID = "P1-js-parse-check"
SEVERITY = Severity.BLOCK
SOURCE = "lessons.md#code-quality"
SCOPE = "repo"

EXTENSIONS = {".js", ".mjs", ".cjs", ".ts"}

def check(ctx: RepoContext) -> List[Verdict]:
    if shutil.which("node") is None:
        return []  # no node installed -> skip, not block

    staged = [
        p for p in ctx.staged_files
        if Path(p).suffix in EXTENSIONS
        and not _is_excluded(p)
    ]
    if not staged:
        return []

    verdicts: List[Verdict] = []
    now = datetime.now(timezone.utc)
    for rel in staged:
        abs_path = ctx.repo_root / rel
        if not abs_path.is_file():
            continue
        result = subprocess.run(
            ["node", "--check", str(abs_path)],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            verdicts.append(Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(ctx.repo_root),
                file=rel,
                line=None,
                detail=f"node --check failed: {result.stderr.strip().splitlines()[0] if result.stderr else 'no stderr'}",
                fix_hint="fix JS/TS syntax; run `node --check <file>` locally",
                source=SOURCE,
                timestamp=now,
            ))
    return verdicts

def _is_excluded(rel: str) -> bool:
    return (
        rel.startswith("node_modules/")
        or rel.startswith("dist/")
        or rel.startswith("build/")
        or "/vendor/" in rel
        or "/.min.js" in rel
    )
```

## Tests

`C:\Sentinel\tests\rules\test_js_parse_check.py`:

1. Clean `.js` file → no verdict.
2. `.js` file with unbalanced paren → BLOCK verdict with line info.
3. `.ts` file with syntax error → BLOCK (node --check handles TS parse fine for
   type-erased code, but for TS-specific syntax the rule should skip gracefully
   — see note below).
4. `.min.js` excluded.
5. `node_modules/` excluded.
6. No node binary available → rule no-ops (returns []), does not BLOCK.
7. Non-staged files are not checked.

## Open questions

- **TypeScript caveat:** `node --check` only parses *runnable* JS, not TS
  syntax like `interface` / `type`. For `.ts` files consider either (a) skip,
  (b) shell out to `tsc --noEmit`, or (c) use `@typescript-eslint/parser` via
  a node wrapper. Defer until a TS-heavy repo hits the rule.
- **Non-staged working-tree changes:** Sentinel's hook is pre-push, so it
  checks staged (committed) files by default. Verify this matches
  `RepoContext.staged_files` semantics in `sentinel/core/repo_context.py`.
- **Speed ceiling:** 50 `.js` files × 10ms = 500ms. Still within budget. But
  a repo with 1000 changed JS files in one push (unusual) could hit 10s. Add
  a soft cap: if staged JS > 200 files, skip with WARN and surface in
  `sentinel-findings.md`.

## Prerequisites

1. Target repo must be git-tracked. (HTA is now tracked as of 2026-04-15; this
   was the blocker that gated this rule's value.)
2. Sentinel hook must be installed in the repo:
   `python -m sentinel install-hook --repo <path>`.

## Rule-count update when implemented

Update `MEMORY.md` sentinel.md from "11 rules" → "12 rules". Update
`README.md` and any rule-count prose in dashboard.
