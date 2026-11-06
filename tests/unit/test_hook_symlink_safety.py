"""Reject symbolic-link pre-push entries before install or uninstall.

All fixtures are local, synthetic Git repos; no network, external Git remotes,
publication content, credentials or bypass controls are involved.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from sentinel.hook.installer import (
    HookInstallError,
    install_hook,
    is_sentinel_hook,
    uninstall_hook,
)


def _repo(tmp_path: Path) -> tuple[Path, Path, Path]:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    hooks = repo / ".git" / "hooks"
    return repo, hooks / "pre-push", hooks / "pre-push.sentinel-backup"


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlinks unavailable on this runner: {type(error).__name__}")


@pytest.mark.parametrize("operation", [install_hook, uninstall_hook])
def test_external_hook_symlink_is_preserved(operation, tmp_path: Path) -> None:
    repo, hook, backup = _repo(tmp_path)
    external = tmp_path / "shared-pre-push"
    original = b"#!/bin/sh\necho synthetic-external-hook\n"
    external.write_bytes(original)
    _symlink(hook, external)

    with pytest.raises(HookInstallError, match="symbolic|symlink"):
        operation(repo)

    assert hook.is_symlink()
    assert external.read_bytes() == original
    assert not backup.exists()


def test_dangling_hook_symlink_is_not_followed(tmp_path: Path) -> None:
    repo, hook, backup = _repo(tmp_path)
    missing = tmp_path / "must-not-be-created"
    _symlink(hook, missing)

    with pytest.raises(HookInstallError, match="symbolic|symlink"):
        install_hook(repo)

    assert hook.is_symlink()
    assert not missing.exists()
    assert not backup.exists()


@pytest.mark.parametrize("operation", [install_hook, uninstall_hook])
def test_backup_symlink_is_not_followed(operation, tmp_path: Path) -> None:
    repo, hook, backup = _repo(tmp_path)
    install_hook(repo)
    assert is_sentinel_hook(hook)
    original_hook = hook.read_bytes()

    external = tmp_path / "shared-backup"
    original_backup = b"#!/bin/sh\necho synthetic-backup\n"
    external.write_bytes(original_backup)
    _symlink(backup, external)

    with pytest.raises(HookInstallError, match="symbolic|symlink"):
        operation(repo)

    assert is_sentinel_hook(hook)
    assert hook.read_bytes() == original_hook
    assert backup.is_symlink()
    assert external.read_bytes() == original_backup


def test_regular_existing_hook_still_chains_and_restores(tmp_path: Path) -> None:
    repo, hook, backup = _repo(tmp_path)
    original = b"#!/bin/sh\necho synthetic-user-hook\n"
    hook.write_bytes(original)

    install_hook(repo)
    assert is_sentinel_hook(hook)
    assert backup.is_file() and not backup.is_symlink()
    assert backup.read_bytes() == original

    uninstall_hook(repo)
    assert hook.is_file() and not hook.is_symlink()
    assert hook.read_bytes() == original
    assert not backup.exists()
