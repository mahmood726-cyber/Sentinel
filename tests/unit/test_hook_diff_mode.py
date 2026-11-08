"""Diff coverage contracts for the stdin-driven pre-push scanner."""
from __future__ import annotations

import pytest

from sentinel.hook.payload import make_hook_script
from tests.unit.test_hook_pushed_refs import commit, push, push_repo, seed_remote


def test_hook_uses_diff_mode_by_default(push_repo):
    """Scan the pushed range, leaving unchanged baseline defects out."""
    repo, _ = push_repo
    commit(repo, "baseline.py", bad=True)
    seed_remote(repo, "main")
    commit(repo, "changed.py")
    output = push(repo, "main")
    assert "(1 files)" in output


def test_hook_honors_explicit_diff_base_env(push_repo, monkeypatch):
    """An explicit base expands coverage without hiding the pushed range."""
    repo, _ = push_repo
    base = commit(repo, "clean.py")
    commit(repo, "baseline.py", bad=True)
    seed_remote(repo, "main")
    commit(repo, "tip.py")
    monkeypatch.setenv("SENTINEL_DIFF_BASE", base)
    push(repo, "main", blocked=True)
    commit(repo, "pushed.py", bad=True)
    monkeypatch.setenv("SENTINEL_DIFF_BASE", "HEAD")
    output = push(repo, "main", blocked=True)
    assert "pushed.py" in output


def test_hook_supports_full_scan_opt_out(push_repo, monkeypatch):
    """Full mode includes unchanged files in the pushed snapshot."""
    repo, _ = push_repo
    commit(repo, "baseline.py", bad=True)
    seed_remote(repo, "main")
    commit(repo, "tip.py")
    monkeypatch.setenv("SENTINEL_DIFF_BASE", "full")
    push(repo, "main", blocked=True)


def test_hook_scan_invocation_uses_scan_args(push_repo, monkeypatch):
    """The helper receives stdin and safely handles an empty override."""
    script = make_hook_script("block")
    assert '| python -P -m sentinel.hook.push "$1"' in script
    assert "printf '%s' \"$PUSH_INPUT\"" in script
    repo, _ = push_repo
    commit(repo, "bad.py", bad=True)
    monkeypatch.setenv("SENTINEL_DIFF_BASE", "")
    push(repo, "main", blocked=True)


def test_hook_falls_back_to_full_scan_when_no_base_resolves(push_repo):
    """An empty remote triggers full coverage, including non-tip files."""
    repo, _ = push_repo
    commit(repo, "baseline.py", bad=True)
    commit(repo, "tip.py")
    output = push(repo, "main", blocked=True)
    assert "FULL TREE" in output


def test_hook_marker_still_present():
    """The SENTINEL_MARKER banner must remain intact so the installer can
    detect Sentinel-installed hooks vs. user hooks."""
    from sentinel.hook.payload import SENTINEL_MARKER
    script = make_hook_script("block")
    assert SENTINEL_MARKER in script


def test_hook_block_and_warn_modes_both_supported():
    """The mode flag still bakes into the MODE= line."""
    block_script = make_hook_script("block")
    warn_script = make_hook_script("warn")
    assert 'MODE="${SENTINEL_MODE:-block}"' in block_script
    assert 'MODE="${SENTINEL_MODE:-warn}"' in warn_script


def test_hook_invalid_mode_raises():
    with pytest.raises(ValueError):
        make_hook_script("invalid-mode")
