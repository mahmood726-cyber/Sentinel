"""Tests for P0-force-push-config (audit P1-4 enforcement).

Regression guard: fails if `git-always-force-push = true` (or a force-push git
alias) reappears in a committed config file — the exact catastrophic-class
setting the 2026-06-20 infra audit found and the security posture forbids.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.yaml_loader import load_yaml_rule


RULE_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "yaml" / "P0-force-push-config.yaml"
)


def _git_repo(path: Path, files: dict[str, str]) -> None:
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    for rel, content in files.items():
        f = path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "-A"], check=True)


def test_fires_on_force_push_true(tmp_path: Path):
    _git_repo(tmp_path, {"config.toml": "model = 'x'\ngit-always-force-push = true\n"})
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert len(verdicts) >= 1
    assert all(v.rule_id == "P0-force-push-config" for v in verdicts)
    assert all(v.severity == Severity.BLOCK for v in verdicts)


def test_silent_on_force_push_false(tmp_path: Path):
    _git_repo(tmp_path, {"config.toml": "git-always-force-push = false\n"})
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert verdicts == []


def test_fires_on_force_push_quoted_true(tmp_path: Path):
    _git_repo(tmp_path, {"agent.toml": 'git-always-force-push = "true"\n'})
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert len(verdicts) >= 1


def test_force_with_lease_alias_is_allowed(tmp_path: Path):
    # --force-with-lease is the safe, reviewed form — must NOT trip the rule.
    _git_repo(tmp_path, {".gitconfig": "[alias]\n  pushf = !git push --force-with-lease\n"})
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert verdicts == []
