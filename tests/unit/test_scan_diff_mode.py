"""Tests for `sentinel scan --diff` and the path-filter mechanism it relies on.

The --diff flag installs a module-level path filter on sentinel.io.git_files
before the rule loop runs; iter_repo_files honours the filter so each rule
scans only the changed-file subset rather than the whole tree.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from sentinel.io.git_files import (
    get_path_filter, iter_repo_files, set_path_filter,
)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A tiny git repo with 4 files for path-filter shaped tests."""
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "t@example.com"],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "Test"],
        check=True, capture_output=True,
    )
    for name in ("a.py", "b.py", "c.py", "d.py"):
        (tmp_path / name).write_text(f"# {name}\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", "."],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-m", "init"],
        check=True, capture_output=True,
    )
    return tmp_path


def test_path_filter_default_is_none():
    """Module-level state must default to None so existing scans aren't
    accidentally filtered when --diff is not requested."""
    # The fixture may leave the filter set; reset for hygiene.
    set_path_filter(None)
    assert get_path_filter() is None


def test_set_path_filter_round_trip():
    try:
        set_path_filter(frozenset({"a.py"}))
        assert get_path_filter() == frozenset({"a.py"})
        set_path_filter(None)
        assert get_path_filter() is None
    finally:
        set_path_filter(None)


def test_iter_repo_files_unfiltered_yields_all(repo):
    """No filter installed: all 4 .py files yielded."""
    set_path_filter(None)
    try:
        names = sorted(p.name for p in iter_repo_files(repo, "*.py"))
        assert names == ["a.py", "b.py", "c.py", "d.py"]
    finally:
        set_path_filter(None)


def test_iter_repo_files_filtered_yields_subset(repo):
    """Filter installed: only files in the set are yielded."""
    try:
        set_path_filter(frozenset({"a.py", "c.py"}))
        names = sorted(p.name for p in iter_repo_files(repo, "*.py"))
        assert names == ["a.py", "c.py"]
    finally:
        set_path_filter(None)


def test_iter_repo_files_filter_with_no_matches(repo):
    """Filter excludes everything: empty iteration, not crash."""
    try:
        set_path_filter(frozenset({"nonexistent.py"}))
        names = list(iter_repo_files(repo, "*.py"))
        assert names == []
    finally:
        set_path_filter(None)


def test_iter_repo_files_filter_normalised_to_forward_slash(repo):
    """Filter set uses forward-slash paths even on Windows. iter_repo_files
    must normalise the git-yielded paths before consulting the filter so
    Windows-style backslashes from internal lookups still match."""
    try:
        # Filter uses forward-slash form (the canonical relative-path shape).
        set_path_filter(frozenset({"b.py"}))
        names = sorted(p.name for p in iter_repo_files(repo, "*.py"))
        assert names == ["b.py"]
    finally:
        set_path_filter(None)


def test_collect_changed_files_includes_untracked(repo):
    """The --diff helper picks up untracked files (not just diff vs HEAD)."""
    # Add a new untracked file.
    (repo / "new.py").write_text("# new\n", encoding="utf-8")
    # Import the collector — it lives in the scan CLI module.
    from sentinel.cli.scan import _collect_changed_files
    changed = _collect_changed_files(repo, "HEAD")
    assert "new.py" in changed


def test_collect_changed_files_includes_unstaged_edit(repo):
    """Edits to a tracked file (unstaged) are picked up."""
    (repo / "a.py").write_text("# a edited\n", encoding="utf-8")
    from sentinel.cli.scan import _collect_changed_files
    changed = _collect_changed_files(repo, "HEAD")
    assert "a.py" in changed


def test_collect_changed_files_no_changes_returns_empty(repo):
    """Clean tree → empty set (the CLI special-cases this with 'nothing to scan')."""
    from sentinel.cli.scan import _collect_changed_files
    changed = _collect_changed_files(repo, "HEAD")
    assert changed == set()
