"""Preserve the original Git hook's execute permissions when chaining.

Only deterministic local synthetic Git repositories are used.  No external
remotes, publications, credentials, or bypass controls are involved.
"""
from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

from sentinel.hook.installer import install_hook, is_sentinel_hook, uninstall_hook


pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="Git hook executable bits and chmod permissions are POSIX-specific",
)


def _repo(tmp_path: Path) -> tuple[Path, Path, Path]:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    hooks_dir = repo / ".git" / "hooks"
    return repo, hooks_dir / "pre-push", hooks_dir / "pre-push.sentinel-backup"


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_disabled_existing_hook_remains_disabled_during_install_and_restore(
    tmp_path: Path,
) -> None:
    repo, hook, backup = _repo(tmp_path)
    original = b"#!/bin/sh\nexit 79\n"
    hook.write_bytes(original)
    hook.chmod(0o644)  # Git correctly ignores a pre-push hook without +x.

    install_hook(repo)
    assert is_sentinel_hook(hook)
    assert _mode(hook) & 0o111  # Sentinel itself must be executable.
    assert backup.read_bytes() == original
    assert _mode(backup) == 0o644  # The inactive user hook must stay inactive.

    uninstall_hook(repo)
    assert hook.read_bytes() == original
    assert _mode(hook) == 0o644
    assert not backup.exists()


def test_enabled_existing_hook_preserves_owner_group_permissions(
    tmp_path: Path,
) -> None:
    repo, hook, backup = _repo(tmp_path)
    original = b"#!/bin/sh\nexit 0\n"
    hook.write_bytes(original)
    hook.chmod(0o750)

    install_hook(repo)
    assert backup.read_bytes() == original
    assert _mode(backup) == 0o750

    uninstall_hook(repo)
    assert hook.read_bytes() == original
    assert _mode(hook) == 0o750


def test_new_hook_is_executable_without_original_and_uninstall_removes_it(
    tmp_path: Path,
) -> None:
    repo, hook, backup = _repo(tmp_path)
    install_hook(repo)
    assert is_sentinel_hook(hook)
    assert _mode(hook) & 0o100
    assert not backup.exists()
    uninstall_hook(repo)
    assert not hook.exists()
