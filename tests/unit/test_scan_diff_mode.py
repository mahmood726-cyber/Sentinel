"""Tests for `sentinel scan --diff` and the path-filter mechanism it relies on.

The --diff flag installs a module-level path filter on sentinel.io.git_files
before the rule loop runs; iter_repo_files honours the filter so each rule
scans only the changed-file subset rather than the whole tree.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from sentinel.core import RepoContext, ScanMode
from sentinel.io.git_files import (
    get_path_filter, iter_repo_files, iter_tree_or_filter, path_allowed,
    set_path_filter,
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


# --- path_allowed helper -------------------------------------------------

def test_path_allowed_true_when_no_filter(tmp_path):
    """No active filter → every path allowed (full-scan behavior unchanged)."""
    set_path_filter(None)
    try:
        assert path_allowed(tmp_path, tmp_path / "anything.html") is True
    finally:
        set_path_filter(None)


def test_path_allowed_respects_filter(tmp_path):
    try:
        set_path_filter(frozenset({"in.html"}))
        assert path_allowed(tmp_path, tmp_path / "in.html") is True
        assert path_allowed(tmp_path, tmp_path / "out.html") is False
        # A path outside root can't be in the changed set.
        assert path_allowed(tmp_path, Path("/elsewhere/x.html")) is False
    finally:
        set_path_filter(None)


# --- regression: rglob-based rules must honor --diff scope ----------------
#
# citation_cascade walks the tree with root.rglob("*") and read_text()s every
# *.md / *.html. Before the path_allowed guard it ignored the --diff filter, so
# a --diff scan re-read every 5 MB dashboard in a 14k-file repo and ran 18+ min
# (incident 2026-06-12). This proves the guard scopes the rule to changed files.

def _git_repo_with_two_bad_dois(tmp_path: Path) -> Path:
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@e.com"],
                   check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "T"],
                   check=True, capture_output=True)
    # Malformed DOI (10.<non-digits>/...) → citation_cascade BLOCK in each file.
    bad = "See doi:10.notreal/xyz for details.\n"
    (tmp_path / "changed.md").write_text(bad, encoding="utf-8")
    (tmp_path / "unchanged.md").write_text(bad, encoding="utf-8")
    return tmp_path


def test_citation_cascade_unfiltered_flags_both(tmp_path):
    from sentinel.rules.plugins import citation_cascade
    repo = _git_repo_with_two_bad_dois(tmp_path)
    set_path_filter(None)
    try:
        ctx = RepoContext(repo_root=repo, mode=ScanMode.REPO)
        files = {v.file for v in citation_cascade.check(ctx)}
        assert files == {"changed.md", "unchanged.md"}
    finally:
        set_path_filter(None)


def test_citation_cascade_diff_filter_scopes_to_changed(tmp_path):
    """With a --diff filter active, the rule must NOT read/flag unchanged.md."""
    from sentinel.rules.plugins import citation_cascade
    repo = _git_repo_with_two_bad_dois(tmp_path)
    try:
        set_path_filter(frozenset({"changed.md"}))
        ctx = RepoContext(repo_root=repo, mode=ScanMode.REPO)
        files = {v.file for v in citation_cascade.check(ctx)}
        assert files == {"changed.md"}, (
            "citation_cascade ignored the --diff path filter and scanned "
            "files outside the changed set"
        )
    finally:
        set_path_filter(None)


# --- iter_tree_or_filter: skip the whole-tree walk when filtered ----------

def test_iter_tree_or_filter_walks_all_without_filter(tmp_path):
    (tmp_path / "a.html").write_text("x", encoding="utf-8")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "b.html").write_text("y", encoding="utf-8")
    set_path_filter(None)
    try:
        names = {p.name for p in iter_tree_or_filter(tmp_path) if p.is_file()}
        assert {"a.html", "b.html"} <= names
    finally:
        set_path_filter(None)


def test_iter_tree_or_filter_yields_only_filter_when_active(tmp_path):
    """When a filter is active the helper yields ONLY the changed files and
    never walks the tree (the per-rule ~3s stat-walk the optimization removes)."""
    (tmp_path / "a.html").write_text("x", encoding="utf-8")
    (tmp_path / "b.html").write_text("y", encoding="utf-8")
    try:
        set_path_filter(frozenset({"a.html"}))
        names = sorted(p.name for p in iter_tree_or_filter(tmp_path))
        assert names == ["a.html"]
    finally:
        set_path_filter(None)


def test_iter_tree_or_filter_skips_filtered_nonexistent_paths(tmp_path):
    """A path in the filter set that doesn't exist on disk is silently skipped
    (e.g. a deleted file in the changed set)."""
    (tmp_path / "a.html").write_text("x", encoding="utf-8")
    try:
        set_path_filter(frozenset({"a.html", "deleted.html"}))
        names = sorted(p.name for p in iter_tree_or_filter(tmp_path))
        assert names == ["a.html"]
    finally:
        set_path_filter(None)


# --- YAML engine honors the filter (the dominant --diff cost) -------------

def test_yaml_iter_matching_files_honors_filter(repo):
    """The YAML rule engine's single file-iteration chokepoint must scope to the
    changed set under --diff. Before the fix every YAML rule (P0-hardcoded-local
    -path et al.) read_text()'d every matching file regardless of --diff — the
    dominant cost of the 18+ min stall (incident 2026-06-12)."""
    from sentinel.registry.yaml_loader import (
        _git_tracked_files, _iter_matching_files,
    )
    tracked = _git_tracked_files(repo)
    assert tracked is not None and len(tracked) == 4  # a.py..d.py
    try:
        set_path_filter(frozenset({"a.py", "c.py"}))
        rels = sorted(rel for _p, rel in _iter_matching_files(
            repo, ["**/*.py"], [], tracked))
        assert rels == ["a.py", "c.py"]
    finally:
        set_path_filter(None)


def test_yaml_iter_matching_files_unfiltered_yields_all(repo):
    from sentinel.registry.yaml_loader import (
        _git_tracked_files, _iter_matching_files,
    )
    tracked = _git_tracked_files(repo)
    set_path_filter(None)
    try:
        rels = sorted(rel for _p, rel in _iter_matching_files(
            repo, ["**/*.py"], [], tracked))
        assert rels == ["a.py", "b.py", "c.py", "d.py"]
    finally:
        set_path_filter(None)
