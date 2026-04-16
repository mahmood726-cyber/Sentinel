"""Tests for P1-js-lockfile-present.

If a repo has package.json, exactly one of package-lock.json / yarn.lock /
pnpm-lock.yaml / bun.lockb should be present. Missing lockfile => WARN
(reproducibility risk: fresh clones install drifted versions).

Triggering incident: HTA Artifact shipped to GitHub without
package-lock.json, which meant `npm install` on CI could get different
versions than local tests ran against.
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "js_lockfile_present.py"
)

MINIMAL_PKG = '{"name":"demo","version":"1.0.0"}'
MINIMAL_LOCK = '{"name":"demo","lockfileVersion":3}'


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_no_package_json_no_verdict(tmp_path: Path):
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_package_json_with_npm_lockfile_clean(tmp_path: Path):
    _write(tmp_path / "package.json", MINIMAL_PKG)
    _write(tmp_path / "package-lock.json", MINIMAL_LOCK)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_package_json_with_yarn_lock_clean(tmp_path: Path):
    _write(tmp_path / "package.json", MINIMAL_PKG)
    _write(tmp_path / "yarn.lock", "# yarn lockfile v1\n")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_package_json_with_pnpm_lock_clean(tmp_path: Path):
    _write(tmp_path / "package.json", MINIMAL_PKG)
    _write(tmp_path / "pnpm-lock.yaml", "lockfileVersion: '6.0'\n")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_package_json_without_any_lockfile_warns(tmp_path: Path):
    _write(tmp_path / "package.json", MINIMAL_PKG)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.rule_id == "P1-js-lockfile-present"
    assert v.severity == Severity.WARN
    assert "lockfile" in v.detail.lower()


def test_portfolio_scope_inactive(tmp_path: Path):
    _write(tmp_path / "package.json", MINIMAL_PKG)
    pi = tmp_path / "ProjectIndex"
    pi.mkdir()
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    assert rule.check(ctx) == []
