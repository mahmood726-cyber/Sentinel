"""P1-test-module-collision: BLOCK when two `test_*.py` files share a
basename across directories with the same pytest import name.

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

This rule discovers tracked `test_*.py` files, groups by basename and
resolves each import name using the longest contiguous chain of tracked
`__init__.py` package markers. An inner package marker is insufficient
when its ancestor lacks one: two paths can still import under the same
short name. Different resolved names remain clean. In --diff scans, the full tracked
inventory is comparison context; verdicts cover changed colliding test
paths and deleted ancestor package markers that provably merge import names.
Unrelated changes and unrelated older collisions do not block pushes.

Severity is BLOCK because the failure mode is invisible — pytest
collects without error and the missing tests never run.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import get_path_filter, iter_repo_files
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

    # Compare against the full tracked test inventory even in --diff mode:
    # the unchanged test module may be the OTHER half of a collision.
    # Only report the changed side below, avoiding historical BLOCK noise
    # when a push modifies unrelated content.
    active_filter = get_path_filter()
    by_name: dict[str, list[Path]] = defaultdict(list)
    for path in iter_repo_files(
        root, "test_*.py", PY_EXCLUDE_DIRS, respect_path_filter=False,
    ):
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

    # A deleted ancestor __init__.py can merge previously distinct pytest
    # import names without changing either test file. The --diff path filter
    # contains the deleted marker, but not its unchanged test descendants.
    # A marker still present in the tracked inventory cannot be that cause.
    removed_markers = (
        [
            root / rel for rel in sorted(active_filter)
            if Path(rel).name == "__init__.py" and root / rel not in package_markers
        ]
        if active_filter is not None else []
    )
    reported_markers: set[Path] = set()

    def import_name(p: Path, markers: set[Path]) -> str:
        parts = [p.stem]
        parent = p.parent
        while parent != root and (parent / "__init__.py") in markers:
            parts.append(parent.name)
            parent = parent.parent
        return ".".join(reversed(parts))

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
            by_import_name[import_name(p, package_markers)].append(p)

        for module_name, colliding in by_import_name.items():
            if len(colliding) < 2:
                continue
            for p in colliding:
                rel = p.relative_to(root).as_posix()
                if active_filter is not None and rel not in active_filter:
                    continue
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

            # Under --diff, the only changed path may be a removed ancestor
            # package marker. Report it only if restoring that marker would
            # separate names that now collide: unrelated marker deletions and
            # content-only edits must not block normal pushes.
            for marker in removed_markers:
                if marker in reported_markers:
                    continue
                restored_names = {
                    import_name(p, package_markers | {marker}) for p in colliding
                }
                if len(restored_names) < 2:
                    continue
                rel = marker.relative_to(root).as_posix()
                colliding_rels = ", ".join(sorted(
                    p.relative_to(root).as_posix() for p in colliding
                ))
                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=SEVERITY,
                    repo=str(root),
                    file=rel,
                    line=1,
                    detail=(
                        f"Missing tracked package marker {rel} merges "
                        f"{colliding_rels} into pytest import name "
                        f"{module_name}. Both test modules must remain collectible"
                    ),
                    fix_hint=(
                        "restore and track this __init__.py package marker, "
                        "or rename a conflicting test module"
                    ),
                    source=SOURCE,
                    timestamp=now,
                ))
                reported_markers.add(marker)
    return verdicts
