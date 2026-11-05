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

    # A local __init__.py that is not tracked will disappear after push,
    # so it must not suppress a test-module collision. Reuse the same
    # tracked-file discovery contract as the test-module inventory. Package
    # markers are cross-file context, even when a --diff scan changes only
    # the test modules, so ignore the diff filter for this metadata query.
    if not any(len(paths) > 1 for paths in by_name.values()):
        return verdicts
    package_markers = set(iter_repo_files(
        root, "__init__.py", PY_EXCLUDE_DIRS, respect_path_filter=False,
    ))

    for name, paths in by_name.items():
        if len(paths) < 2:
            continue

        # Pytest uses the longest contiguous package path when importing
        # test modules. A tracked init in the immediate parent is not enough:
        # north/sub/test_x.py and south/sub/test_x.py both import as
        # sub.test_x if north/ and south/ lack tracked package markers.
        # Distinct inner packages, however, must remain clean.
        by_import_name: dict[str, list[Path]] = defaultdict(list)
        for p in paths:
            parts = [p.stem]
            parent = p.parent
            while parent != root and (parent / "__init__.py") in package_markers:
                parts.append(parent.name)
                parent = parent.parent
            by_import_name[".".join(reversed(parts))].append(p)

        for module_name, colliding in by_import_name.items():
            if len(colliding) < 2:
                continue
            for p in colliding:
                rel = p.relative_to(root).as_posix()
                other_rels = ", ".join(sorted(
                    q.relative_to(root).as_posix()
                    for q in colliding if q != p
                ))
                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=SEVERITY,
                    repo=str(root),
                    file=rel,
                    line=1,
                    detail=(
                        f"{name} imports as {module_name} and collides with: "
                        f"{other_rels}. Pytest cannot collect both modules "
                        "under the default prepend importer"
                    ),
                    fix_hint=(
                        "track missing ancestor __init__.py package markers, "
                        "or rename one of the colliding files"
                    ),
                    source=SOURCE,
                    timestamp=now,
                ))
    return verdicts
