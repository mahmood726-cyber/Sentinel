"""A replaced user pre-push hook must never be lost to a stale backup.

All paths, hooks and history below are deterministic synthetic Git fixtures.
"""
from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from sentinel.hook.installer import HookInstallError, install_hook, is_sentinel_hook, uninstall_hook


def _repo_with_chained_hook(tmp_path: Path) -> tuple[Path, Path, Path, bytes]:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    hooks = repo / ".git" / "hooks"
    hook = hooks / "pre-push"
    original = b"#!/bin/sh\necho synthetic-original\n"
    hook.write_bytes(original)
    install_hook(repo)
    assert is_sentinel_hook(hook)
    backup = hooks / "pre-push.sentinel-backup"
    assert backup.read_bytes() == original
    return repo, hook, backup, original


def test_reinstall_does_not_clobber_external_replacement(tmp_path: Path) -> None:
    repo, hook, backup, original = _repo_with_chained_hook(tmp_path)
    replacement = b"#!/bin/sh\necho synthetic-replacement\n"
    hook.write_bytes(replacement)

    with pytest.raises(HookInstallError, match="modified|replaced|conflict"):
        install_hook(repo)

    assert hook.read_bytes() == replacement
    assert backup.read_bytes() == original


def test_uninstall_does_not_clobber_external_replacement(tmp_path: Path) -> None:
    repo, hook, backup, original = _repo_with_chained_hook(tmp_path)
    replacement = b"#!/bin/sh\necho synthetic-replacement\n"
    hook.write_bytes(replacement)

    with pytest.raises(HookInstallError, match="modified|replaced|conflict"):
        uninstall_hook(repo)

    assert hook.read_bytes() == replacement
    assert backup.read_bytes() == original


def test_intact_sentinel_reinstall_and_uninstall_still_restores_original(tmp_path: Path) -> None:
    repo, hook, backup, original = _repo_with_chained_hook(tmp_path)

    install_hook(repo)
    assert is_sentinel_hook(hook)
    assert backup.read_bytes() == original

    uninstall_hook(repo)
    assert hook.read_bytes() == original
    assert not backup.exists()


def test_new_unrelated_hook_without_prior_backup_is_still_chained(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    hooks = repo / ".git" / "hooks"
    original = b"#!/bin/sh\necho synthetic-user-hook\n"
    (hooks / "pre-push").write_bytes(original)

    install_hook(repo)
    assert is_sentinel_hook(hooks / "pre-push")
    assert (hooks / "pre-push.sentinel-backup").read_bytes() == original
