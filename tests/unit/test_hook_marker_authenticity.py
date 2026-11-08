"""Protect non-Sentinel pre-push hooks that contain a copied Sentinel banner.

These are isolated synthetic Git repositories; no external remotes or pushes.
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
from sentinel.hook.payload import SENTINEL_MARKER, make_hook_script


def _repo(tmp_path: Path) -> tuple[Path, Path, Path]:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    hooks = repo / ".git" / "hooks"
    return repo, hooks / "pre-push", hooks / "pre-push.sentinel-backup"


def _different_hook_with_banner() -> bytes:
    return f"#!/bin/sh\n{SENTINEL_MARKER}\necho synthetic-unrelated-hook\n".encode("utf-8")


@pytest.mark.parametrize("operation", [install_hook, uninstall_hook])
def test_marker_only_replacement_cannot_be_overwritten(operation, tmp_path: Path) -> None:
    repo, hook, backup = _repo(tmp_path)
    original = b"#!/bin/sh\necho synthetic-original\n"
    hook.write_bytes(original)
    install_hook(repo)
    assert backup.read_bytes() == original

    replacement = _different_hook_with_banner()
    hook.write_bytes(replacement)
    with pytest.raises(HookInstallError, match="modified|replaced|unrecognized|conflict"):
        operation(repo)

    assert hook.read_bytes() == replacement
    assert backup.read_bytes() == original


@pytest.mark.parametrize("operation", [install_hook, uninstall_hook])
def test_unrecognized_banner_without_backup_is_not_treated_as_sentinel(
    operation, tmp_path: Path
) -> None:
    repo, hook, backup = _repo(tmp_path)
    replacement = _different_hook_with_banner()
    hook.write_bytes(replacement)

    with pytest.raises(HookInstallError, match="modified|unrecognized|conflict"):
        operation(repo)

    assert hook.read_bytes() == replacement
    assert not backup.exists()


def test_canonical_block_and_warn_hooks_are_recognized(tmp_path: Path) -> None:
    repo, hook, backup = _repo(tmp_path)
    for mode in ("block", "warn"):
        install_hook(repo, mode=mode)
        assert is_sentinel_hook(hook)
        assert hook.read_text(encoding="utf-8") == make_hook_script(mode)
        assert not backup.exists()
    uninstall_hook(repo)
    assert not hook.exists()


def test_normal_chaining_and_reinstall_preserve_original(tmp_path: Path) -> None:
    repo, hook, backup = _repo(tmp_path)
    original = b"#!/bin/sh\necho synthetic-user-hook\n"
    hook.write_bytes(original)
    install_hook(repo)
    first = hook.read_bytes()
    install_hook(repo)
    assert hook.read_bytes() == first
    assert backup.read_bytes() == original
    uninstall_hook(repo)
    assert hook.read_bytes() == original
    assert not backup.exists()
