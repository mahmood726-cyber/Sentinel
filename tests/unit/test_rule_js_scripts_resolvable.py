"""Tests for P1-js-scripts-resolvable.

Every entry in package.json's 'scripts' section that references a local
file path (node scripts/x.js, bash ./deploy.sh, Rscript analysis.R) should
resolve to an existing file. Missing targets => WARN.

Triggering incident: HTA Artifact's package.json declared 8+ npm scripts
(quality:gate, review:panel, validate:reference, etc.) that referenced
files in scripts/ — but scripts/ wasn't in git. Anyone cloning fresh
would have hit ENOENT on every npm script.
"""
from __future__ import annotations

import json
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "js_scripts_resolvable.py"
)


def _write_pkg(tmp_path: Path, scripts: dict) -> None:
    pkg = {"name": "demo", "version": "1.0.0", "scripts": scripts}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")


def _write_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("console.log('ok');\n", encoding="utf-8")


def test_no_package_json_no_verdict(tmp_path: Path):
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_package_json_no_scripts_no_verdict(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"name":"x"}', encoding="utf-8")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_scripts_all_resolve_clean(tmp_path: Path):
    _write_pkg(tmp_path, {
        "build": "node scripts/build.js",
        "test": "jest",  # bare command — not a path reference
    })
    _write_file(tmp_path / "scripts" / "build.js")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_missing_script_file_warns(tmp_path: Path):
    _write_pkg(tmp_path, {"build": "node scripts/build.js"})
    # scripts/build.js does NOT exist
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.rule_id == "P1-js-scripts-resolvable"
    assert v.severity == Severity.WARN
    assert "build" in v.detail


def test_multiple_missing_scripts_multi_verdict(tmp_path: Path):
    _write_pkg(tmp_path, {
        "build": "node scripts/build.js",
        "deploy": "bash ./deploy.sh",
        "test": "jest",  # bare, should not flag
    })
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 2
    names = sorted(v.detail for v in verdicts)
    assert any("build" in n for n in names)
    assert any("deploy" in n for n in names)


def test_bare_commands_not_flagged(tmp_path: Path):
    # bare commands like `jest`, `eslint .`, `tsc` don't reference local files
    _write_pkg(tmp_path, {
        "test": "jest",
        "lint": "eslint .",
        "type": "tsc --noEmit",
    })
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_npm_run_chain_not_flagged(tmp_path: Path):
    # composite scripts like `npm run build && npm run test` don't reference files
    _write_pkg(tmp_path, {
        "build": "echo ok",
        "test": "echo ok",
        "ci": "npm run build && npm run test",
    })
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_malformed_package_json_no_verdict(tmp_path: Path):
    # Rule should no-op on broken JSON rather than crash; another rule
    # can flag malformed package.json if desired.
    (tmp_path / "package.json").write_text("{not json", encoding="utf-8")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_portfolio_scope_inactive(tmp_path: Path):
    _write_pkg(tmp_path, {"build": "node scripts/missing.js"})
    pi = tmp_path / "ProjectIndex"
    pi.mkdir()
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    assert rule.check(ctx) == []
