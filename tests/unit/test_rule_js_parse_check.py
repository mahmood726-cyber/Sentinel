"""Tests for P1-js-parse-check.

The rule shells out to `node --check` on every .js/.mjs/.cjs file under the
repo root (excluding node_modules, dist, build, vendor, coverage, .git, and
*.min.js). Syntax failures produce BLOCK verdicts.

Background: the 2026-04-15 maicSTC.js incident shipped a missing closing paren
to a "submission-ready" repo because nothing parsed the file before push.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "js_parse_check.py"
)

CLEAN_JS = "function add(a, b) { return a + b; }\n"
BROKEN_JS = "function broken(a, b) { return a + b)); }\n"  # extra `))`


pytestmark = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="node binary not on PATH; rule tests require node --check",
)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_clean_js_no_verdict(tmp_path: Path):
    _write(tmp_path / "src" / "ok.js", CLEAN_JS)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_broken_js_blocks(tmp_path: Path):
    _write(tmp_path / "src" / "bad.js", BROKEN_JS)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.rule_id == "P1-js-parse-check"
    assert v.severity == Severity.BLOCK
    assert v.file == "src/bad.js"


def test_skip_file_marker_suppresses_parse_check(tmp_path: Path):
    _write(tmp_path / "src" / "archived_bad.js", "// sentinel:skip-file\n" + BROKEN_JS)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_node_modules_excluded(tmp_path: Path):
    _write(tmp_path / "node_modules" / "junk" / "bad.js", BROKEN_JS)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_min_js_excluded(tmp_path: Path):
    _write(tmp_path / "dist-out" / "bundle.min.js", BROKEN_JS)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_dist_dir_excluded(tmp_path: Path):
    _write(tmp_path / "dist" / "out.js", BROKEN_JS)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_portfolio_scope_inactive(tmp_path: Path):
    _write(tmp_path / "src" / "bad.js", BROKEN_JS)
    pi = tmp_path / "ProjectIndex"
    pi.mkdir()
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    assert rule.check(ctx) == []


def test_typescript_files_skipped(tmp_path: Path):
    # node --check can't parse TS-specific syntax; rule must skip .ts to avoid
    # false positives on type annotations.
    ts_with_types = "function f(x: number): number { return x + 1; }\n"
    _write(tmp_path / "src" / "typed.ts", ts_with_types)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_mjs_and_cjs_checked(tmp_path: Path):
    _write(tmp_path / "src" / "bad.mjs", BROKEN_JS)
    _write(tmp_path / "src" / "bad.cjs", BROKEN_JS)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    files = sorted(v.file for v in verdicts)
    assert files == ["src/bad.cjs", "src/bad.mjs"]
