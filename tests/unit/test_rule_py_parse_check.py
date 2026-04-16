"""Tests for P1-py-parse-check.

Walks .py files under repo root, runs `python -m py_compile`, BLOCKs on
SyntaxError. Triggering incident: saarc-e156-students had 6 generator
scripts with f-string apostrophe SyntaxErrors — f"  {'Karachi's Global
Trial Share'}" — which had sat on disk unmodified for weeks because no
one ever ran them. Parallel rule to P1-js-parse-check (2026-04-15).

Excludes: __pycache__, .venv, venv, .git, node_modules, dist, build,
.pytest_cache, site-packages.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "py_parse_check.py"
)

CLEAN_PY = "def add(a, b):\n    return a + b\n"
BROKEN_PY = 'print(f"  {\'broken\'s string\'}")\n'  # the saarc bug shape


pytestmark = pytest.mark.skipif(
    shutil.which("python") is None and shutil.which(sys.executable) is None,
    reason="python binary required for py_compile",
)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_clean_py_no_verdict(tmp_path: Path):
    _write(tmp_path / "src" / "ok.py", CLEAN_PY)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_broken_py_blocks(tmp_path: Path):
    _write(tmp_path / "src" / "bad.py", BROKEN_PY)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.rule_id == "P1-py-parse-check"
    assert v.severity == Severity.BLOCK
    assert v.file == "src/bad.py"


def test_venv_excluded(tmp_path: Path):
    _write(tmp_path / ".venv" / "site-packages" / "broken.py", BROKEN_PY)
    _write(tmp_path / "venv" / "lib" / "broken.py", BROKEN_PY)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_pycache_excluded(tmp_path: Path):
    _write(tmp_path / "__pycache__" / "broken.py", BROKEN_PY)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_site_packages_excluded(tmp_path: Path):
    _write(tmp_path / "lib" / "site-packages" / "broken.py", BROKEN_PY)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_multiple_broken_multi_verdict(tmp_path: Path):
    _write(tmp_path / "a.py", BROKEN_PY)
    _write(tmp_path / "b.py", BROKEN_PY)
    _write(tmp_path / "clean.py", CLEAN_PY)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 2
    files = sorted(v.file for v in verdicts)
    assert files == ["a.py", "b.py"]


def test_portfolio_scope_inactive(tmp_path: Path):
    _write(tmp_path / "bad.py", BROKEN_PY)
    pi = tmp_path / "pi"
    pi.mkdir()
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    assert rule.check(ctx) == []
