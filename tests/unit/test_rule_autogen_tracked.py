"""Tests for P2-autogen-tracked.

Known auto-generated files should not be tracked in git. This rule WARNs
when any are. Pattern generalizes 2026-04-15 `progress_md_not_gitignored`
to cover the broader set of Sentinel/Overmind auto-logs and nightly
reports discovered during the 2026-04-16 portfolio audit.

Covered filenames (by basename):
  - PROGRESS.md
  - DECISIONS.md
  - STUCK_FAILURES.md / .jsonl
  - sentinel-findings.md / .jsonl
  - review-findings.md / .jsonl (pre-rename Sentinel output)
  - stability_state.json (Overmind)
  - latest.json under data/nightly_reports/

Trigger incidents:
  - shifaa + overmind (2026-04-16): tracked review-findings.md + auto-gen
    nightly/stability files, producing thousands of lines of diff noise.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "autogen_tracked.py"
)


def _git_init_with_file(tmp_path: Path, name: str, content: str = "x") -> None:
    (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(content, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t",
         "add", "."], cwd=tmp_path, check=True
    )
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t",
         "commit", "-q", "-m", "init"], cwd=tmp_path, check=True
    )


def test_no_git_no_verdict(tmp_path: Path):
    (tmp_path / "PROGRESS.md").write_text("x", encoding="utf-8")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_empty_git_no_verdict(tmp_path: Path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_progress_md_tracked_warns(tmp_path: Path):
    _git_init_with_file(tmp_path, "PROGRESS.md")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "P2-autogen-tracked"
    assert verdicts[0].severity == Severity.WARN
    assert "PROGRESS.md" in verdicts[0].detail


def test_review_findings_md_tracked_warns(tmp_path: Path):
    _git_init_with_file(tmp_path, "review-findings.md")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert "review-findings.md" in verdicts[0].detail


def test_stuck_failures_jsonl_tracked_warns(tmp_path: Path):
    _git_init_with_file(tmp_path, "STUCK_FAILURES.jsonl")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert "STUCK_FAILURES.jsonl" in verdicts[0].detail


def test_stability_state_json_tracked_warns(tmp_path: Path):
    _git_init_with_file(tmp_path, "data/stability_state.json")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert "stability_state.json" in verdicts[0].detail


def test_multiple_autogen_multi_verdict(tmp_path: Path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "PROGRESS.md").write_text("x", encoding="utf-8")
    (tmp_path / "DECISIONS.md").write_text("x", encoding="utf-8")
    (tmp_path / "sentinel-findings.md").write_text("x", encoding="utf-8")
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t",
         "add", "."], cwd=tmp_path, check=True
    )
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t",
         "commit", "-q", "-m", "init"], cwd=tmp_path, check=True
    )
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 3
    files = sorted(v.detail for v in verdicts)
    assert any("PROGRESS.md" in f for f in files)
    assert any("DECISIONS.md" in f for f in files)
    assert any("sentinel-findings.md" in f for f in files)


def test_untracked_but_present_no_verdict(tmp_path: Path):
    # File exists on disk but is untracked (not in index) -> no verdict
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "PROGRESS.md").write_text("x", encoding="utf-8")
    # Don't add/commit — file stays untracked
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_unrelated_md_not_flagged(tmp_path: Path):
    _git_init_with_file(tmp_path, "README.md")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_portfolio_scope_inactive(tmp_path: Path):
    _git_init_with_file(tmp_path, "PROGRESS.md")
    pi = tmp_path / "pi"
    pi.mkdir()
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    assert rule.check(ctx) == []
