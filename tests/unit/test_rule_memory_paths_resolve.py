"""Tests for P2-memory-paths-resolve.

Portfolio-scope rule that reads Claude memory files under the configured
memory dir, grep-extracts Windows absolute paths from backtick-wrapped
references, and WARNs on paths that don't resolve on disk.

Triggering lesson (2026-04-16): sentinel.md shipped 3 wrong paths that
took a separate audit turn to reconcile. This rule catches the drift at
scan time.

Memory dir is configurable via `SENTINEL_MEMORY_DIR` env var for test
injection.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "memory_paths_resolve.py"
)


@pytest.fixture
def patched_memory_dir(tmp_path: Path, monkeypatch):
    """Point the rule at a temp memory dir."""
    memory = tmp_path / "memory"
    memory.mkdir()
    monkeypatch.setenv("SENTINEL_MEMORY_DIR", str(memory))
    return memory


def test_no_memory_dir_no_verdict(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SENTINEL_MEMORY_DIR", str(tmp_path / "nonexistent"))
    rule = load_plugin_rule(PLUGIN_PATH)
    pi = tmp_path / "pi"
    pi.mkdir()
    ctx = RepoContext(repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi)
    assert rule.check(ctx) == []


def test_all_paths_resolve_clean(patched_memory_dir: Path, tmp_path: Path):
    # Write a memory file referencing a real directory
    real_dir = tmp_path / "real_project"
    real_dir.mkdir()
    (patched_memory_dir / "note.md").write_text(
        f"Project lives at `{real_dir}`\n", encoding="utf-8"
    )
    rule = load_plugin_rule(PLUGIN_PATH)
    pi = tmp_path / "pi"
    pi.mkdir()
    ctx = RepoContext(repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi)
    assert rule.check(ctx) == []


def test_missing_path_warns(patched_memory_dir: Path, tmp_path: Path):
    ghost = tmp_path / "ghost_project"
    # Don't create ghost
    (patched_memory_dir / "stale.md").write_text(
        f"Project lives at `{ghost}`\n", encoding="utf-8"
    )
    rule = load_plugin_rule(PLUGIN_PATH)
    pi = tmp_path / "pi"
    pi.mkdir()
    ctx = RepoContext(repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.rule_id == "P2-memory-paths-resolve"
    assert v.severity == Severity.WARN
    assert "ghost_project" in v.detail


def test_glob_patterns_skipped(patched_memory_dir: Path, tmp_path: Path):
    # Glob templates aren't real paths — rule must skip them
    (patched_memory_dir / "glob.md").write_text(
        "See `C:\\\\Projects\\\\*_LivingMeta` and `C:\\\\Projects\\\\LivingMeta_*`\n",
        encoding="utf-8",
    )
    rule = load_plugin_rule(PLUGIN_PATH)
    pi = tmp_path / "pi"
    pi.mkdir()
    ctx = RepoContext(repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi)
    assert rule.check(ctx) == []


def test_downloads_references_skipped(patched_memory_dir: Path, tmp_path: Path):
    # Historical "was here, now gone" prose — rule skips Downloads/ refs
    (patched_memory_dir / "hist.md").write_text(
        "Project used to live at `C:\\\\Users\\\\user\\\\Downloads\\\\old_thing\\\\`\n",
        encoding="utf-8",
    )
    rule = load_plugin_rule(PLUGIN_PATH)
    pi = tmp_path / "pi"
    pi.mkdir()
    ctx = RepoContext(repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi)
    assert rule.check(ctx) == []


def test_repo_scope_inactive(patched_memory_dir: Path, tmp_path: Path):
    ghost = tmp_path / "nope"
    (patched_memory_dir / "stale.md").write_text(
        f"at `{ghost}`\n", encoding="utf-8"
    )
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_multiple_missing_multi_verdict(patched_memory_dir: Path, tmp_path: Path):
    ghost_a = tmp_path / "ghost_a"
    ghost_b = tmp_path / "ghost_b"
    (patched_memory_dir / "note.md").write_text(
        f"- `{ghost_a}`\n- `{ghost_b}`\n", encoding="utf-8"
    )
    rule = load_plugin_rule(PLUGIN_PATH)
    pi = tmp_path / "pi"
    pi.mkdir()
    ctx = RepoContext(repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 2
    files = sorted(v.detail for v in verdicts)
    assert any("ghost_a" in f for f in files)
    assert any("ghost_b" in f for f in files)
