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


# Cross-platform by design: the rule's regex is Windows-path-only, but
# tests work around tmp_path shape differences by using hardcoded
# `C:/nonexistent_*` strings in memory files and monkeypatching
# `_available_drives` to include 'C' so the path is treated as "drive
# mounted, path missing" (WARN) rather than "drive offline" (INFO).


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


def test_default_memory_dir_derives_from_home():
    """Regression (P1-6): the default memory dir must derive from the live
    home dir, not a hardcoded `C:\\Users\\user\\...C--Users-user...` literal.
    The literal silently disabled the rule on every machine whose user is not
    `user`. Assert the default sits under home and the slug tracks home."""
    from sentinel.rules.plugins import memory_paths_resolve as mod

    default = mod._default_memory_dir()
    assert str(default).startswith(str(Path.home()))
    assert default.name == "memory"
    assert "user" not in mod._home_project_slug() or "user" in str(Path.home()).lower()
    # The slug must encode the home path with separators flattened to '-'.
    assert mod._home_project_slug() == str(Path.home()).replace(":", "-").replace("\\", "-").replace("/", "-")


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
    """Uses a hardcoded Windows-style path (rule regex is Windows-only)
    and patches the loaded plugin's `_available_drives` to include 'C'
    so the verdict is WARN (not INFO "drive offline"). Runs cross-
    platform. The patch targets `rule._check.__globals__` because
    load_plugin_rule creates a fresh module, not the one returned by
    `import`."""
    (patched_memory_dir / "stale.md").write_text(
        "Project lives at `C:/nonexistent_ghost_project_7f3a`\n",
        encoding="utf-8",
    )
    rule = load_plugin_rule(PLUGIN_PATH)
    rule._check.__globals__["_available_drives"] = lambda: {"C"}
    pi = tmp_path / "pi"
    pi.mkdir()
    ctx = RepoContext(repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.rule_id == "P2-memory-paths-resolve"
    assert v.severity == Severity.WARN
    assert "nonexistent_ghost_project_7f3a" in v.detail


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
    (patched_memory_dir / "note.md").write_text(
        "- `C:/nonexistent_ghost_a_8b41`\n"
        "- `C:/nonexistent_ghost_b_c9e2`\n",
        encoding="utf-8",
    )
    rule = load_plugin_rule(PLUGIN_PATH)
    rule._check.__globals__["_available_drives"] = lambda: {"C"}
    pi = tmp_path / "pi"
    pi.mkdir()
    ctx = RepoContext(repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 2
    files = sorted(v.detail for v in verdicts)
    assert any("ghost_a" in f for f in files)
    assert any("ghost_b" in f for f in files)


def test_offline_drive_emits_info_not_warn(patched_memory_dir: Path, tmp_path: Path):
    # Reference a path on a drive that doesn't exist on this machine
    # (Q: or Z: — typically unmapped on Windows).
    # Path will be MISSING and drive will be in the unavailable set →
    # INFO, not WARN.
    (patched_memory_dir / "offline.md").write_text(
        r"Project at `Z:\ghost\project`" + "\n", encoding="utf-8"
    )
    rule = load_plugin_rule(PLUGIN_PATH)
    pi = tmp_path / "pi"
    pi.mkdir()
    ctx = RepoContext(repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.INFO
    assert "offline drive Z" in verdicts[0].detail
