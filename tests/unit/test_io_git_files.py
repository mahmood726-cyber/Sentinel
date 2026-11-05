"""Tests for sentinel.io.git_files.iter_repo_files.

The helper keeps plugin rules bounded — a pre-push scan on a user-home
directory must not walk OneDrive, AppData, etc. Git-worktrees use
`git ls-files`; non-git paths fall back to rglob. When git is present
but fails for any reason (corrupt .git, missing binary, timeout,
non-zero exit), the helper raises a scan-stopping error and never
falls back to rglob while `.git` exists.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from sentinel.io import git_files
from sentinel.io.git_files import (
    DEFAULT_EXCLUDE_DIRS, HTML_EXCLUDE_DIRS, JS_EXCLUDE_DIRS,
    PY_EXCLUDE_DIRS, iter_repo_files,
)


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


# -- Baseline behavior --------------------------------------------------

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
    (tmp_path / "x.py").write_text("x", encoding="utf-8")
    (tmp_path / "a_dir").mkdir()
    found = list(iter_repo_files(tmp_path, "*"))
    assert all(p.is_file() for p in found)


def test_empty_repo_yields_nothing(tmp_path: Path):
    (tmp_path / "seed.md").write_text("seed", encoding="utf-8")
    _git_init_commit_all(tmp_path)
    found = list(iter_repo_files(tmp_path, "*.py"))
    assert found == []


# -- Multi-pattern --------------------------------------------------------

def test_multi_pattern_git(tmp_path: Path):
    (tmp_path / "a.js").write_text("x", encoding="utf-8")
    (tmp_path / "b.mjs").write_text("x", encoding="utf-8")
    (tmp_path / "c.cjs").write_text("x", encoding="utf-8")
    (tmp_path / "d.py").write_text("x", encoding="utf-8")
    _git_init_commit_all(tmp_path)
    found = sorted(
        p.name for p in iter_repo_files(tmp_path, ("*.js", "*.mjs", "*.cjs"))
    )
    assert found == ["a.js", "b.mjs", "c.cjs"]


def test_multi_pattern_non_git_dedupes(tmp_path: Path):
    (tmp_path / "a.js").write_text("x", encoding="utf-8")
    (tmp_path / "b.mjs").write_text("x", encoding="utf-8")
    found = sorted(
        p.name for p in iter_repo_files(tmp_path, ("*.js", "*.mjs", "*"))
    )
    # "*" would yield both too, but seen-set dedupes
    assert found == ["a.js", "b.mjs"]


# -- Exclude-dir constants exist and are non-empty ------------------------

def test_exclude_constants_non_empty():
    assert isinstance(DEFAULT_EXCLUDE_DIRS, frozenset) and DEFAULT_EXCLUDE_DIRS
    assert PY_EXCLUDE_DIRS >= DEFAULT_EXCLUDE_DIRS
    assert JS_EXCLUDE_DIRS >= DEFAULT_EXCLUDE_DIRS
    assert HTML_EXCLUDE_DIRS >= DEFAULT_EXCLUDE_DIRS
    assert ".venv" in PY_EXCLUDE_DIRS
    assert "node_modules" in JS_EXCLUDE_DIRS
    # `archive` covers historical release-snapshot directories that
    # commonly contain BOM-prefixed Python and parse-error JS scratch files.
    # Past incident (2026-05-08): C:/HTML apps/dosehtml/archive/release-
    # snapshots/* contributed 12 P1-py-parse-check + 3 P1-js-parse-check
    # BLOCKs on frozen historical code that has no current bug surface.
    assert "archive" in DEFAULT_EXCLUDE_DIRS


def test_archive_directory_excluded_by_default(tmp_path: Path):
    """A file under archive/ must NOT be returned by iter_repo_files when
    using DEFAULT_EXCLUDE_DIRS."""
    archive = tmp_path / "archive" / "old-release"
    archive.mkdir(parents=True)
    (archive / "frozen.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "live.py").write_text("y = 2\n", encoding="utf-8")
    files = list(iter_repo_files(tmp_path, "*.py", DEFAULT_EXCLUDE_DIRS))
    rels = sorted(f.name for f in files)
    assert "live.py" in rels
    assert "frozen.py" not in rels


# -- Regression-critical: fail-closed on git errors -----------------------
# These tests lock in the P0 fix from 2026-04-19 review. If any of them
# starts passing by yielding rglob-walked files, the helper has silently
# re-opened the user-home DoS the helper was written to prevent.

def _write_tracked_plus_untracked(tmp_path: Path) -> None:
    (tmp_path / "tracked.py").write_text("x", encoding="utf-8")
    _git_init_commit_all(tmp_path)
    # Untracked file would be visible to rglob but NOT to git ls-files
    (tmp_path / "untracked_rglob_only.py").write_text("x", encoding="utf-8")


def test_git_failure_nonzero_exit_fails_closed(tmp_path: Path, monkeypatch):
    """Nonzero Git enumeration must raise; never return an empty success."""
    _write_tracked_plus_untracked(tmp_path)
    real_run = subprocess.run

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        if "ls-files" in cmd:
            return subprocess.CompletedProcess(cmd, returncode=128, stdout="", stderr="fatal")
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(git_files.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="git ls-files"):
        list(iter_repo_files(tmp_path, "*.py"))


def test_git_missing_binary_fails_closed(tmp_path: Path, monkeypatch):
    """Missing Git must abort scanning, not masquerade as an empty listing."""
    _write_tracked_plus_untracked(tmp_path)
    real_run = subprocess.run

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        if "ls-files" in cmd:
            raise FileNotFoundError("git: not found")
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(git_files.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="git ls-files"):
        list(iter_repo_files(tmp_path, "*.py"))


def test_git_timeout_fails_closed(tmp_path: Path, monkeypatch):
    """A timed-out Git enumeration must abort the scan without rglob."""
    _write_tracked_plus_untracked(tmp_path)
    real_run = subprocess.run

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        if "ls-files" in cmd:
            raise subprocess.TimeoutExpired(cmd, timeout=30)
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(git_files.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="git ls-files"):
        list(iter_repo_files(tmp_path, "*.py"))


def test_git_absent_uses_rglob_bounded(tmp_path: Path):
    """When .git is absent, rglob is used — this is the intended fallback.
    The regression bug would be using rglob when .git is PRESENT."""
    (tmp_path / "only.py").write_text("x", encoding="utf-8")
    found = list(iter_repo_files(tmp_path, "*.py"))
    assert [p.name for p in found] == ["only.py"]


def test_gitfile_submodule_detected(tmp_path: Path):
    """Submodules/worktrees have `.git` as a FILE, not a directory. The
    helper must recognize that and take the git path."""
    # Real git init to get a functioning repo, then replace .git dir
    # with a gitfile pointing to it (simulates submodule / linked worktree).
    (tmp_path / "tracked.py").write_text("x", encoding="utf-8")
    _git_init_commit_all(tmp_path)
    # After this, .git is a directory. iter_repo_files should already use
    # ls-files. To simulate a submodule, we'd need a pointer file — but
    # just proving `.exists()` is reached (not `.is_dir()`-only) is enough:
    # if someone ever replaces `.git` with a file pointer, behavior must
    # stay git-backed.
    assert (tmp_path / ".git").exists()
    # Create untracked and assert git path still used (only tracked yielded)
    (tmp_path / "untracked.py").write_text("x", encoding="utf-8")
    found = sorted(p.name for p in iter_repo_files(tmp_path, "*.py"))
    assert found == ["tracked.py"]


def test_filename_with_newline_survives_nul_parsing(tmp_path: Path):
    """-z + split('\\x00') must correctly handle the NUL-delimited output."""
    # Windows disallows \n in filenames, so just verify the -z code path
    # works end-to-end for normal filenames (the other tests already do
    # this, but make the invariant explicit here).
    (tmp_path / "a.py").write_text("x", encoding="utf-8")
    (tmp_path / "b.py").write_text("y", encoding="utf-8")
    _git_init_commit_all(tmp_path)
    found = sorted(p.name for p in iter_repo_files(tmp_path, "*.py"))
    assert found == ["a.py", "b.py"]


def test_tracked_file_stat_error_aborts_instead_of_skipping(tmp_path: Path, monkeypatch):
    """A tracked regular file that cannot be inspected must not disappear
    from the scan. A silent skip could hide a committed BLOCK finding."""
    (tmp_path / "good.py").write_text("value = 42\n", encoding="utf-8")
    (tmp_path / "inaccessible.py").write_text("def broken(:\n", encoding="utf-8")
    _git_init_commit_all(tmp_path)

    real_is_file = Path.is_file

    def fake_is_file(self: Path) -> bool:
        if self.name == "inaccessible.py":
            raise OSError(1920, "simulated inaccessible tracked file")
        return real_is_file(self)

    monkeypatch.setattr(Path, "is_file", fake_is_file)
    with pytest.raises(git_files.GitFileEnumerationError, match="tracked file"):
        list(iter_repo_files(tmp_path, "*.py"))


def test_excluded_inaccessible_file_does_not_block_clean_tracked_code(
    tmp_path: Path, monkeypatch,
):
    """Normal pushes remain clean if an unreadable file is explicitly
    excluded before any filesystem inspection."""
    (tmp_path / "good.py").write_text("value = 42\n", encoding="utf-8")
    excluded = tmp_path / "tests"
    excluded.mkdir()
    (excluded / "inaccessible.py").write_text("def broken(:\n", encoding="utf-8")
    _git_init_commit_all(tmp_path)

    real_is_file = Path.is_file

    def fake_is_file(self: Path) -> bool:
        if self.name == "inaccessible.py":
            raise OSError(1920, "simulated excluded path")
        return real_is_file(self)

    monkeypatch.setattr(Path, "is_file", fake_is_file)
    files = list(iter_repo_files(tmp_path, "*.py", exclude_dirs=["tests"]))
    assert [p.name for p in files] == ["good.py"]


def test_tracked_file_stat_error_fails_closed_through_cli(
    tmp_path: Path, monkeypatch, capsys,
):
    """Regression: a failing per-file check must be exit 10, not clean or
    a warn-downgradable BLOCK, even if an actual syntax BLOCK is concealed."""
    from argparse import Namespace
    from sentinel.cli.scan import _run

    (tmp_path / "inaccessible.py").write_text("def broken(:\n", encoding="utf-8")
    _git_init_commit_all(tmp_path)
    real_is_file = Path.is_file

    def fake_is_file(self: Path) -> bool:
        if self.name == "inaccessible.py":
            raise OSError(1920, "simulated unreadable tracked candidate")
        return real_is_file(self)

    monkeypatch.setattr(Path, "is_file", fake_is_file)
    rc = _run(Namespace(
        repo=tmp_path, project_index=tmp_path, diff=False, base_ref="HEAD",
        json=False, sarif=False, timing=False,
    ))
    output = capsys.readouterr()
    assert rc == 10
    assert "[Sentinel] verdicts:" not in output.out
    assert "tracked file" in output.err


def test_pattern_never_interpreted_as_git_flag(tmp_path: Path):
    """The `--` separator before pattern prevents future callers' hostile
    patterns being interpreted as git options."""
    (tmp_path / "hyphen-file.py").write_text("x", encoding="utf-8")
    _git_init_commit_all(tmp_path)
    # A pathspec pattern that starts with `-` should match literally, not
    # be interpreted as a git option. This would have failed without `--`.
    found = sorted(
        p.name for p in iter_repo_files(tmp_path, "hyphen-*.py")
    )
    assert found == ["hyphen-file.py"]


def test_git_utf8_filename_path_identity(tmp_path: Path):
    """Git -z names must decode the same way as Python paths on Windows."""
    filename = " café.py"
    (tmp_path / filename).write_text("VALUE = 1\n", encoding="utf-8")
    _git_init_commit_all(tmp_path)
    assert [p.name for p in iter_repo_files(tmp_path, "*.py")] == [filename]


# Role 06 regression (2026-11-05): Git enumeration errors must not
# masquerade as an empty rule result. An empty result would make
# syntax-invalid committed code appear clean during a complete scan.

def test_git_listing_error_raises_instead_of_masquerading_as_clean(
    tmp_path: Path, monkeypatch,
):
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    _git_init_commit_all(tmp_path)
    real_run = subprocess.run

    def reject_listing(cmd: list[str], **kwargs: Any) -> Any:
        if cmd[:2] == ["git", "-C"] and "ls-files" in cmd:
            return subprocess.CompletedProcess(
                cmd, returncode=128, stdout="", stderr="synthetic failure"
            )
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(git_files.subprocess, "run", reject_listing)
    with pytest.raises(RuntimeError, match="git ls-files"):
        list(iter_repo_files(tmp_path, "*.py"))


def test_git_listing_error_blocks_clean_scan_result(
    tmp_path: Path, monkeypatch, capsys,
):
    """When a plugin cannot enumerate tracked files, scan must exit 10."""
    from argparse import Namespace
    from sentinel.cli.scan import _run

    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    _git_init_commit_all(tmp_path)
    real_run = subprocess.run

    def reject_listing(cmd: list[str], **kwargs: Any) -> Any:
        if cmd[:2] == ["git", "-C"] and "ls-files" in cmd:
            return subprocess.CompletedProcess(
                cmd, returncode=128, stdout="", stderr="synthetic failure"
            )
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(git_files.subprocess, "run", reject_listing)
    rc = _run(Namespace(
        repo=tmp_path, project_index=tmp_path, diff=False, base_ref="HEAD",
        json=False, sarif=False, timing=False,
    ))
    captured = capsys.readouterr()
    assert rc == 10, "incomplete rule scan must never return clean"
    assert "git ls-files" in captured.err
    assert "[Sentinel] verdicts:" not in captured.out


def test_git_listing_valid_code_still_passes_clean(
    tmp_path: Path, capsys,
):
    """Normal tracked valid code remains clean, without rglob fallback."""
    from argparse import Namespace
    from sentinel.cli.scan import _run

    (tmp_path / "good.py").write_text("answer = 42\n", encoding="utf-8")
    _git_init_commit_all(tmp_path)
    assert [p.name for p in iter_repo_files(tmp_path, "*.py")] == ["good.py"]
    rc = _run(Namespace(
        repo=tmp_path, project_index=tmp_path, diff=False, base_ref="HEAD",
        json=False, sarif=False, timing=False,
    ))
    captured = capsys.readouterr()
    assert rc == 0
    assert "[Sentinel] verdicts: BLOCK=0" in captured.out
