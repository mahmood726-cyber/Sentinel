"""A failed backup preparation must not silently disable an existing pre-push guard.

All fixtures are synthetic local Git repositories; no network or publication data.
"""
from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from sentinel.hook.installer import (
    HookInstallError,
    install_hook,
    is_sentinel_hook,
    uninstall_hook,
)


def _repo_with_user_hook(tmp_path: Path) -> tuple[Path, Path, Path, Path, bytes]:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    hooks = repo / ".git" / "hooks"
    hook = hooks / "pre-push"
    backup = hooks / "pre-push.sentinel-backup"
    original = b"#!/bin/sh\necho synthetic-existing-gate\nexit 1\n"
    hook.write_bytes(original)
    return repo, hooks, hook, backup, original


def test_backup_chmod_error_preserves_original_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, hooks, hook, backup, original = _repo_with_user_hook(tmp_path)
    original_chmod = Path.chmod

    def deny_backup_mode_change(path: Path, mode: int, *args, **kwargs):
        # Cover both the old directly-written backup and the new staged sibling.
        if path.parent == hooks and (
            path.name == backup.name or path.name.startswith(".pre-push.sentinel-")
        ):
            raise PermissionError("synthetic backup chmod failure")
        return original_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "chmod", deny_backup_mode_change)

    with pytest.raises(HookInstallError, match="preserve|backup"):
        install_hook(repo)

    assert hook.read_bytes() == original
    assert not is_sentinel_hook(hook)
    assert not backup.exists()
    assert not list(hooks.glob(".pre-push.sentinel-*"))


def test_existing_hook_is_chained_and_restored_on_normal_install(tmp_path: Path) -> None:
    repo, hooks, hook, backup, original = _repo_with_user_hook(tmp_path)

    install_hook(repo)
    assert is_sentinel_hook(hook)
    assert backup.read_bytes() == original
    assert not list(hooks.glob(".pre-push.sentinel-*"))

    uninstall_hook(repo)
    assert hook.read_bytes() == original
    assert not backup.exists()
