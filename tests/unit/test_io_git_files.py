"""Tests for sentinel.io.git_files.iter_repo_files.

The helper keeps plugin rules bounded — a pre-push scan on a user-home
directory must not walk OneDrive, AppData, etc. Git-worktrees use
`git ls-files`; non-git paths fall back to rglob.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from sentinel.io.git_files import iter_repo_files


def _git_init_commit_all(repo: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "."],
        cwd=repo, check=True,
    )
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t",
         "commit", "-q", "-m", "init"],
        cwd=repo, check=True,
    )


def test_non_git_uses_rglob(tmp_path: Path):
    (tmp_path / "a.py").write_text("x", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.py").write_text("y", encoding="utf-8")
    found = sorted(p.name for p in iter_repo_files(tmp_path, "*.py"))
    assert found == ["a.py", "b.py"]


def test_git_worktree_lists_only_tracked(tmp_path: Path):
    (tmp_path / "tracked.py").write_text("x", encoding="utf-8")
    _git_init_commit_all(tmp_path)
    (tmp_path / "untracked.py").write_text("z", encoding="utf-8")
    found = sorted(p.name for p in iter_repo_files(tmp_path, "*.py"))
    assert found == ["tracked.py"]


def test_exclude_dirs_filters_parts(tmp_path: Path):
    (tmp_path / "keep.py").write_text("x", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.py").write_text("y", encoding="utf-8")
    found = sorted(
        p.name for p in iter_repo_files(
            tmp_path, "*.py", exclude_dirs=["node_modules"]
        )
    )
    assert found == ["keep.py"]


def test_git_worktree_respects_gitignore(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("ignored/\n", encoding="utf-8")
    (tmp_path / "tracked.py").write_text("x", encoding="utf-8")
    (tmp_path / "ignored").mkdir()
    (tmp_path / "ignored" / "skip.py").write_text("y", encoding="utf-8")
    _git_init_commit_all(tmp_path)
    found = sorted(p.name for p in iter_repo_files(tmp_path, "*.py"))
    assert found == ["tracked.py"]


def test_directories_not_yielded(tmp_path: Path):
    # pattern "*" would normally match both files and dirs via rglob
    (tmp_path / "x.py").write_text("x", encoding="utf-8")
    (tmp_path / "a_dir").mkdir()
    found = list(iter_repo_files(tmp_path, "*"))
    assert all(p.is_file() for p in found)


def test_empty_repo_yields_nothing(tmp_path: Path):
    _git_init_commit_all_empty = _git_init_commit_all
    (tmp_path / "seed.md").write_text("seed", encoding="utf-8")
    _git_init_commit_all_empty(tmp_path)
    found = list(iter_repo_files(tmp_path, "*.py"))
    assert found == []
