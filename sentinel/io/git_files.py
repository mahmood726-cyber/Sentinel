# sentinel:skip-file — module doc cites home-dir path as the incident example
"""Bounded file discovery for plugin rules.

Plugins that need "every .py / .html / .js file in this repo" must NOT
use `Path.rglob("*.py")` when the repo root might be a user home
directory. The previous pre-push hook on `C:/Users/user` stalled for
minutes because `dashboard_stat_orphan` / `py_parse_check` /
`js_parse_check` each rglob-walked the entire user profile, including
OneDrive, AppData, and every installed application's data tree.

The fix: prefer `git ls-files <pattern>` when a worktree is present.
It's fast, honors .gitignore, and is bounded to tracked files — exactly
the set a pre-push scan cares about. Fall back to a bounded rglob only
for non-git paths (tests, ad-hoc runs against a clean tmp_path).

Usage:

    from sentinel.io.git_files import iter_repo_files

    for path in iter_repo_files(
        ctx.repo_root, pattern="*.py", exclude_dirs=EXCLUDE_DIRS
    ):
        ...
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterable, Iterator, Sequence


def iter_repo_files(
    root: Path,
    pattern: str = "*",
    exclude_dirs: Sequence[str] | Iterable[str] = (),
) -> Iterator[Path]:
    """Yield files under `root` matching `pattern`.

    Prefers `git ls-files <pattern>` on git worktrees (fast, bounded,
    gitignore-aware). Falls back to `root.rglob(pattern)` when `root`
    has no `.git` directory.

    `exclude_dirs` is matched against path parts (not full paths), so
    `"node_modules"` excludes any file whose relative path contains a
    `node_modules` component.

    Only files are yielded; directories that happen to match `pattern`
    are skipped.
    """
    excludes = frozenset(exclude_dirs)

    if (root / ".git").is_dir():
        try:
            result = subprocess.run(
                ["git", "-C", str(root), "ls-files", pattern],
                capture_output=True, text=True, timeout=30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            result = None
        if result is not None and result.returncode == 0:
            for rel in result.stdout.splitlines():
                if not rel:
                    continue
                if excludes and any(p in excludes for p in Path(rel).parts):
                    continue
                path = root / rel
                if path.is_file():
                    yield path
            return

    for path in root.rglob(pattern):
        if not path.is_file():
            continue
        if excludes and any(part in excludes for part in path.parts):
            continue
        yield path
