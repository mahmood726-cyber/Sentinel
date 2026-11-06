"""Synthetic negative and valid controls for preserving an existing pre-push gate.

All repositories are local and contain no publications, credentials, or remotes.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

from sentinel.hook.installer import HookInstallError, install_hook, is_sentinel_hook


def _existing_hook(tmp_path: Path) -> tuple[Path, Path, Path, bytes]:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    hooks = repo / ".git" / "hooks"
    hook = hooks / "pre-push"
    backup = hooks / "pre-push.sentinel-backup"
    original = b"#!/bin/sh\necho synthetic-original-check\nexit 1\n"
    hook.write_bytes(original)
    return repo, hook, backup, original


def test_backup_rename_failure_keeps_existing_hook_without_partial_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, hook, backup, original = _existing_hook(tmp_path)
    original_replace = os.replace

    def reject_backup_replace(source, destination):
        if Path(destination) == backup:
            raise PermissionError("synthetic backup rename failure")
        return original_replace(source, destination)

    monkeypatch.setattr(os, "replace", reject_backup_replace)

    with pytest.raises(HookInstallError, match="backup"):
        install_hook(repo)

    assert hook.read_bytes() == original
    assert not is_sentinel_hook(hook)
    assert not backup.exists()
    assert not list(hook.parent.glob(".pre-push.sentinel-*"))


def test_backup_success_preserves_original_for_normal_chaining(
    tmp_path: Path,
) -> None:
    repo, hook, backup, original = _existing_hook(tmp_path)
    install_hook(repo)

    assert is_sentinel_hook(hook)
    assert backup.read_bytes() == original
    assert not list(hook.parent.glob(".pre-push.sentinel-*"))
