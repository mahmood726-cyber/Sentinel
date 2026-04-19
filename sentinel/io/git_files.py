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
when the path is NOT a git worktree (tests, ad-hoc runs).

IMPORTANT: if a git worktree IS present but `git ls-files` fails for any
reason (corrupt .git, missing git binary, timeout, non-zero exit), we
fail closed (return nothing) rather than falling back to rglob. The
rglob fallback inside a broken worktree re-opens the exact DoS this
helper exists to close (see `review-findings.md#P0-1`, 2026-04-19).

Usage:

    from sentinel.io.git_files import iter_repo_files, DEFAULT_EXCLUDE_DIRS

    for path in iter_repo_files(
        ctx.repo_root, pattern="*.py", exclude_dirs=DEFAULT_EXCLUDE_DIRS
    ):
        ...
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterable, Iterator, Sequence


# Exclude-dir sets consumed by plugins. Single source of truth — the
# four plugins previously drifted to 5/10/10/13 separate sets.
DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset({
    ".git", "node_modules", "dist", "build", "__pycache__",
    ".pytest_cache", "vendor", "coverage",
    "playwright-report", "test-results", "htmlcov",
    # Test trees + fixtures are excluded for consistency with
    # yaml_loader.COMMON_EXCLUDES. Rules that specifically want to
    # scan tests (e.g. the py-parse-check of root-level test_*.py)
    # still work because only the `tests` subdir is excluded, not
    # files named `test_*` at the root.
    "tests", "fixtures",
})

PY_EXCLUDE_DIRS: frozenset[str] = DEFAULT_EXCLUDE_DIRS | {
    ".venv", "venv", "site-packages", ".tox", ".eggs",
}

JS_EXCLUDE_DIRS: frozenset[str] = DEFAULT_EXCLUDE_DIRS

HTML_EXCLUDE_DIRS: frozenset[str] = DEFAULT_EXCLUDE_DIRS | {".venv"}


def _is_git_worktree(root: Path) -> bool:
    """Return True if `root` is a git worktree — `.git` may be a directory
    (regular repo) or a file (submodule / linked worktree containing
    `gitdir: ...`)."""
    return (root / ".git").exists()


def iter_repo_files(
    root: Path,
    pattern: str | Sequence[str] = "*",
    exclude_dirs: Sequence[str] | Iterable[str] = (),
) -> Iterator[Path]:
    """Yield files under `root` matching `pattern` (string or sequence).

    Multi-pattern support (`pattern=("*.js", "*.mjs", "*.cjs")`) is
    useful when git can batch pathspecs into a single `ls-files` call,
    avoiding N subprocess spawns.

    On a git worktree: uses `git ls-files -z -- <patterns...>` (fast,
    bounded, gitignore-aware). Any git failure fails closed (returns
    nothing) — never falls back to rglob while `.git` exists.

    On a non-git path: falls back to `root.rglob(pattern)` for each
    pattern in turn, deduplicating.

    `exclude_dirs` is matched against path parts (not full paths), so
    `"node_modules"` excludes any file whose relative path contains a
    `node_modules` component.

    Only regular files are yielded.
    """
    excludes = frozenset(exclude_dirs)
    patterns: list[str] = [pattern] if isinstance(pattern, str) else list(pattern)

    if _is_git_worktree(root):
        try:
            result = subprocess.run(
                ["git", "-C", str(root), "ls-files", "-z", "--", *patterns],
                capture_output=True, text=True, timeout=30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return
        if result.returncode != 0:
            return
        for rel in result.stdout.split("\x00"):
            if not rel:
                continue
            if excludes and any(p in excludes for p in Path(rel).parts):
                continue
            path = root / rel
            if path.is_file():
                yield path
        return

    seen: set[Path] = set()
    for p in patterns:
        for path in root.rglob(p):
            if path in seen:
                continue
            seen.add(path)
            if not path.is_file():
                continue
            if excludes and any(part in excludes for part in path.parts):
                continue
            yield path
