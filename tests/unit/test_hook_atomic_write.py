"""Hook updates must be atomic so an interrupted write cannot disable push checks.

Only synthetic local Git hooks are used. No credentials, papers or network remotes.
"""
from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

from sentinel.hook.installer import install_hook, is_sentinel_hook, uninstall_hook


def _repo(tmp_path: Path) -> tuple[Path, Path, Path]:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    hooks = repo / ".git" / "hooks"
    return repo, hooks / "pre-push", hooks / "pre-push.sentinel-backup"


def _interrupt_replace(monkeypatch: pytest.MonkeyPatch, active: Path) -> None:
    """Model an I/O failure at the final atomic replacement, not an env bypass."""
    original = os.replace

    def fail_on_active(source, destination):
        if Path(destination) == active:
            raise OSError("synthetic atomic-rename failure")
        return original(source, destination)

    monkeypatch.setattr(os, "replace", fail_on_active)


def test_failed_reinstall_keeps_current_hook_executable_and_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, hook, backup = _repo(tmp_path)
    install_hook(repo)
    original = hook.read_bytes()
    _interrupt_replace(monkeypatch, hook)

    with pytest.raises(OSError, match="synthetic atomic-rename failure"):
        install_hook(repo)

    assert hook.read_bytes() == original
    assert is_sentinel_hook(hook)
    if os.name != "nt":  # Windows stat does not expose POSIX execute bits
        assert hook.stat().st_mode & stat.S_IXUSR
    assert not backup.exists()
    assert not list(hook.parent.glob(".pre-push.sentinel-*"))


def test_failed_uninstall_restore_keeps_sentinel_hook_and_original_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, hook, backup = _repo(tmp_path)
    original = b"#!/bin/sh\necho synthetic-user-hook\n"
    hook.write_bytes(original)
    install_hook(repo)
    installed = hook.read_bytes()
    assert backup.read_bytes() == original
    _interrupt_replace(monkeypatch, hook)

    with pytest.raises(OSError, match="synthetic atomic-rename failure"):
        uninstall_hook(repo)

    assert hook.read_bytes() == installed
    assert is_sentinel_hook(hook)
    assert backup.read_bytes() == original
    assert not list(hook.parent.glob(".pre-push.sentinel-*"))


def test_hook_update_never_opens_active_script_for_in_place_truncation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, hook, backup = _repo(tmp_path)
    original = b"#!/bin/sh\necho synthetic-legacy-hook\n"
    hook.write_bytes(original)
    original_write_text = Path.write_text

    def block_in_place_write(path, *args, **kwargs):
        if path == hook:
            raise OSError("synthetic in-place-write failure")
        return original_write_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", block_in_place_write)
    install_hook(repo)

    assert is_sentinel_hook(hook)
    assert backup.read_bytes() == original


def test_uninterrupted_install_and_restore_preserve_valid_hook(
    tmp_path: Path
) -> None:
    repo, hook, backup = _repo(tmp_path)
    original = b"#!/bin/sh\necho synthetic-clean-hook\n"
    hook.write_bytes(original)

    install_hook(repo)
    assert is_sentinel_hook(hook)
    if os.name != "nt":  # Windows stat does not expose POSIX execute bits
        assert hook.stat().st_mode & stat.S_IXUSR
    assert backup.read_bytes() == original
    install_hook(repo)
    assert backup.read_bytes() == original
    uninstall_hook(repo)
    assert hook.read_bytes() == original
    if os.name != "nt":  # Windows stat does not expose POSIX execute bits
        assert hook.stat().st_mode & stat.S_IXUSR
    assert not backup.exists()
