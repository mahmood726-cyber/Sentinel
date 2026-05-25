"""P1-test-module-collision: BLOCK when two `test_*.py` files share a
basename across directories AND at least one directory lacks
`__init__.py`.

Past incident (lessons.md "Module-name collision hides tests",
2026-04-16): AlMizan had `test_al_mizan.py` at the repo root and a
second `test_al_mizan.py` inside `tests/`. With no `__init__.py` in
`tests/`, pytest's rootdir-relative importer saw both as the module
`test_al_mizan`, kept the first, and silently dropped the 30
`unittest.TestCase` tests in the second. The test count went 9 → 39
once `tests/__init__.py` was added.

The fix is one of:
- `touch tests/__init__.py` (subdir becomes a package; the second file
  is then `tests.test_al_mizan`, distinct from the root `test_al_mizan`).
- Rename one of the two files.

This rule walks every `test_*.py` file in the repo, groups by basename,
and flags any group with >1 entry where at least one parent dir lacks
`__init__.py`. The repo root counts as "lacks __init__.py" unless one
is committed there.

Severity is BLOCK because the failure mode is invisible — pytest
collects without error and the missing tests never run.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import iter_repo_files
from sentinel.io.skip_marker import has_skip_marker


ID = "P1-test-module-collision"
SEVERITY = Severity.BLOCK
SOURCE = "lessons.md#python-module--test-collection-traps  (Module-name collision hides tests, 2026-04-16)"
SCOPE = "repo"

MAX_FILE_BYTES = 5_000_000
PY_EXCLUDE_DIRS = (".venv", "venv", "__pycache__", "build", "dist",
                   ".tox", ".pytest_cache", "node_modules", "site-packages")


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    root = ctx.repo_root

    # Bucket test_*.py files by basename.
    by_name: dict[str, list[Path]] = defaultdict(list)
    for path in iter_repo_files(root, "test_*.py", PY_EXCLUDE_DIRS):
        if has_skip_marker(path):
            continue
        by_name[path.name].append(path)

    for name, paths in by_name.items():
        if len(paths) < 2:
            continue
        # Group is a collision candidate. Check: does at least one parent
        # dir lack __init__.py? If yes, pytest's importer will dedupe.
        offending: list[Path] = []
        for p in paths:
            init = p.parent / "__init__.py"
            if not init.is_file():
                offending.append(p)
        if not offending:
            continue
        # Report each collision pair. The first file in `paths` is the
        # "kept" one; the rest are "dropped" by pytest's importer.
        for p in offending:
            rel = p.relative_to(root).as_posix()
            other_rels = ", ".join(
                sorted(q.relative_to(root).as_posix() for q in paths if q != p)
            )
            verdicts.append(Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(root),
                file=rel,
                line=1,
                detail=(
                    f"`{name}` collides with: {other_rels}. "
                    "pytest's rootdir importer keeps one and silently "
                    "drops the others — tests become invisible"
                ),
                fix_hint=(
                    f"add `__init__.py` to `{p.parent.relative_to(root).as_posix() or '.'}`, "
                    "or rename one of the colliding files"
                ),
                source=SOURCE,
                timestamp=now,
            ))
    return verdicts
