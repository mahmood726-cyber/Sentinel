"""Tests for P1-py-package-init-tracked.

Directories whose .py files use relative imports (`from .X import Y`)
need their `__init__.py` tracked in git. Without it, fresh clones fail
with ImportError on any code path that reaches the import.

Trigger incident (2026-04-28):
  - CardioOracle: curate/extract_aact.py used `from .shared import ...`
    but curate/__init__.py was on disk yet untracked. Fresh clone broke
    at step 1 of the README pipeline. Same issue caught in 5 other repos
    during the same audit.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "py_package_init_tracked.py"
)


def _init_repo(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)


def _commit_all(tmp_path: Path) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "."],
        cwd=tmp_path, check=True,
    )
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t",
         "commit", "-q", "-m", "init"],
        cwd=tmp_path, check=True,
    )


def test_no_git_no_verdict(tmp_path: Path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("from .b import c\n", encoding="utf-8")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_init_tracked_no_verdict(tmp_path: Path):
    _init_repo(tmp_path)
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pkg" / "a.py").write_text("from .b import c\n", encoding="utf-8")
    (tmp_path / "pkg" / "b.py").write_text("c = 1\n", encoding="utf-8")
    _commit_all(tmp_path)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_init_missing_warns(tmp_path: Path):
    _init_repo(tmp_path)
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("from .b import c\n", encoding="utf-8")
    (tmp_path / "pkg" / "b.py").write_text("c = 1\n", encoding="utf-8")
    _commit_all(tmp_path)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "P1-py-package-init-tracked"
    assert verdicts[0].severity == Severity.WARN
    assert "pkg/__init__.py" in verdicts[0].detail


def test_init_on_disk_but_untracked_warns(tmp_path: Path):
    """The CardioOracle case exactly: __init__.py exists but never staged."""
    _init_repo(tmp_path)
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("from .b import c\n", encoding="utf-8")
    (tmp_path / "pkg" / "b.py").write_text("c = 1\n", encoding="utf-8")
    _commit_all(tmp_path)
    # Now create __init__.py but don't add it
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert "pkg/__init__.py" in verdicts[0].detail


def test_skips_vendor_dir(tmp_path: Path):
    _init_repo(tmp_path)
    (tmp_path / "vendor" / "pkg").mkdir(parents=True)
    (tmp_path / "vendor" / "pkg" / "a.py").write_text("from .b import c\n", encoding="utf-8")
    _commit_all(tmp_path)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_skips_worktrees_dir(tmp_path: Path):
    """ImpossibleMA false positive on 2026-04-28: worktree subdirs are
    technically separate repos and should be skipped during walk."""
    _init_repo(tmp_path)
    (tmp_path / ".worktrees" / "v1" / "src" / "pkg").mkdir(parents=True)
    (tmp_path / ".worktrees" / "v1" / "src" / "pkg" / "a.py").write_text(
        "from .b import c\n", encoding="utf-8"
    )
    (tmp_path / "real.py").write_text("x = 1\n", encoding="utf-8")
    _commit_all(tmp_path)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_no_relative_imports_no_verdict(tmp_path: Path):
    _init_repo(tmp_path)
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("import os\nimport json\n", encoding="utf-8")
    _commit_all(tmp_path)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_skips_untracked_py_files(tmp_path: Path):
    """Fresh clones don't see untracked files, so they cannot ImportError
    on them. A .py file using relative imports inside a gitignored dir
    (e.g. AppData/, .cmdstan/, .positron/, OneDrive/Backups/) must not
    produce a verdict.

    Triggering observation (2026-05-09 home-config push):
      Sentinel emitted 421 WARNs from this rule, the bulk of which were
      paths inside .cmdstan/, .positron/extensions/, AppData/Local/pypa/,
      and OneDrive backups. None of those .py files are tracked. None of
      them can ImportError on a fresh clone of home-config. All were
      false positives.
    """
    _init_repo(tmp_path)
    (tmp_path / "real.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text(".cmdstan/\n", encoding="utf-8")
    _commit_all(tmp_path)
    # Now create the gitignored .cmdstan dir with a relative-import .py
    # file. The dir-name components (.cmdstan, cmdstan-2.37.0, stan, tbb)
    # are NOT in SKIP_DIR_NAMES, so the walker descends in. The fix has
    # to filter by tracked status, not by dir name.
    pkg = tmp_path / ".cmdstan" / "cmdstan-2.37.0" / "stan" / "tbb"
    pkg.mkdir(parents=True)
    (pkg / "a.py").write_text("from .b import c\n", encoding="utf-8")
    (pkg / "b.py").write_text("c = 1\n", encoding="utf-8")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []
