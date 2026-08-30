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
    # archive/: historical release-snapshot trees and scratch /
    # temp-file holding pens. Past incident (2026-05-08): the
    # C:/HTML apps/dosehtml/archive/release-snapshots/* tree
    # contributed 12 P1-py-parse-check (BOM-prefixed legacy .py)
    # plus 3 P1-js-parse-check (temp_*.js) BLOCKs on code that has
    # no current bug surface. Same principle as `dist`/`vendor`:
    # frozen historical content, not actively-shipped source.
    "archive",
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


# Scan-scoped path filter. When non-None, iter_repo_files only yields
# files whose forward-slash relative path is in this set. Set by
# `sentinel scan --diff` before the rule loop; reset to None after.
# Module-level (not threadlocal) because Sentinel scans single-threaded;
# moving to a context-var if/when we go parallel is mechanical.
_ACTIVE_PATH_FILTER: frozenset[str] | None = None


def set_path_filter(paths: frozenset[str] | None) -> None:
    """Set or clear the scan-scoped path filter. Pass None to disable."""
    global _ACTIVE_PATH_FILTER
    _ACTIVE_PATH_FILTER = paths


def get_path_filter() -> frozenset[str] | None:
    return _ACTIVE_PATH_FILTER


def path_allowed(root: Path, path: Path) -> bool:
    """True if `path` passes the active `--diff` path filter.

    Rules that do their OWN filesystem walk (`rglob` / `os.walk`) instead of
    `iter_repo_files` MUST guard each candidate with this — otherwise they read
    every matching file in the repo regardless of the changed-file scope, and
    `--diff` is no faster than a full scan. That is exactly what stalled a
    `--diff` scan to 18+ min / >1.7 GB on a 14k-file dashboard repo, because
    `citation_cascade` / `claim_grounding` `rglob`-read every 5 MB `*.html`
    (incident 2026-06-12).

    Returns True when no filter is active (i.e. a full scan), so callers can
    guard unconditionally with zero behavior change outside `--diff`. A path
    outside `root` returns False (it cannot be in the changed-file set).
    """
    active = _ACTIVE_PATH_FILTER
    if active is None:
        return True
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        return False
    return rel in active


def iter_tree_or_filter(root: Path, population=None) -> Iterator[Path]:
    """Yield candidate file `Path`s for a rule that would otherwise `rglob("*")`
    the whole tree, then apply its own extension / exclude-dir filtering.

    When a `--diff` filter is active, yield ONLY the changed files (no tree
    walk at all) — otherwise `rglob("*")`-walking + `stat`-ing every entry in a
    16k-file repo costs ~3 s PER rule even when the reads are skipped, which
    keeps `--diff` seconds-slow instead of the intended sub-second. When no
    filter is active, fall back to the full `root.rglob("*")` walk (unchanged
    full-scan behavior). Only existing regular files are yielded.
    """
    active = _ACTIVE_PATH_FILTER
    if active is not None:
        for rel in active:
            p = root / rel
            try:
                if p.is_file():
                    yield p
            except OSError:
                continue
        return
    # Without a declared population this walks the RAW FILESYSTEM. On F:/E156
    # that is 49,079 files against PRESENT's 4,246 -- 91.3% of it .git
    # internals, caches and build output that no push can ship. A rule that
    # declares a population reads the same set as the rest of the engine.
    # MUST also require a git worktree. Without that check, repo_files()
    # returns None on a non-git path and `or frozenset()` turns it into an
    # EMPTY set -- the rule then silently sees nothing, which is precisely
    # the inert-rule failure this whole change exists to close. Caught by
    # 19 test failures on tmp_path fixtures, 2026-08-30.
    if population is not None and _is_git_worktree(root):
        from sentinel.io.population import repo_files
        for rel in sorted(repo_files(root, population) or frozenset()):
            p = root / rel
            try:
                if p.is_file():
                    yield p
            except OSError:
                continue
        return
    yield from root.rglob("*")


def iter_repo_files(
    root: Path,
    pattern: str | Sequence[str] = "*",
    exclude_dirs: Sequence[str] | Iterable[str] = (),
    population=None,
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

    # `population` (sentinel/io/population.py) lets a rule state WHICH file
    # set it is asking about. Default None = the historical behaviour,
    # `git ls-files` = PUBLISHED (tracked only), so an un-migrated rule is
    # unchanged. A rule that declares PRESENT also sees untracked-not-ignored
    # files -- which is what a CORRECTNESS rule wants, because a defect in an
    # untracked script still runs when someone runs it.
    if population is not None and _is_git_worktree(root):
        from sentinel.io.population import repo_files
        import fnmatch as _fnmatch
        rels = repo_files(root, population) or frozenset()
        active_filter = _ACTIVE_PATH_FILTER
        for rel in sorted(rels):
            if excludes and any(x in excludes for x in Path(rel).parts):
                continue
            if active_filter is not None and rel not in active_filter:
                continue
            if not any(_fnmatch.fnmatch(Path(rel).name, pat) for pat in patterns):
                continue
            path = root / rel
            try:
                if path.is_file():
                    yield path
            except OSError:
                continue
        return

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
        active_filter = _ACTIVE_PATH_FILTER
        for rel in result.stdout.split("\x00"):
            if not rel:
                continue
            if excludes and any(p in excludes for p in Path(rel).parts):
                continue
            if active_filter is not None and rel.replace("\\", "/") not in active_filter:
                continue
            path = root / rel
            # `is_file()` can raise OSError on OneDrive placeholders,
            # broken symlinks, and Windows "inaccessible file" states
            # (WinError 1920). Treat any failure as "skip this file"
            # rather than aborting the entire scan.
            try:
                if path.is_file():
                    yield path
            except OSError:
                continue
        return

    seen: set[Path] = set()
    active_filter = _ACTIVE_PATH_FILTER
    for p in patterns:
        for path in root.rglob(p):
            if path in seen:
                continue
            seen.add(path)
            try:
                if not path.is_file():
                    continue
            except OSError:
                continue
            if excludes and any(part in excludes for part in path.parts):
                continue
            if active_filter is not None:
                try:
                    rel = path.relative_to(root).as_posix()
                except ValueError:
                    continue
                if rel not in active_filter:
                    continue
            yield path
