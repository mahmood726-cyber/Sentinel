"""The installed pre-push hook must land in Git's *active* hooks directory.

Synthetic local repositories only; no remote operations or publication data.
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


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    return repo


def _configure_hooks_path(repo: Path, hooks_path: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), "config", "--local", "core.hooksPath", hooks_path],
        check=True,
    )


def test_relative_hooks_path_is_used_for_block_hook(tmp_path: Path):
    repo = _repo(tmp_path)
    _configure_hooks_path(repo, "managed-hooks")
    hooks = repo / "managed-hooks"

    install_hook(repo)
    hook = hooks / "pre-push"
    assert is_sentinel_hook(hook)
    assert 'MODE="${SENTINEL_MODE:-block}"' in hook.read_text(encoding="utf-8")
    assert not (repo / ".git" / "hooks" / "pre-push").exists()

    uninstall_hook(repo)
    assert not hook.exists()


def test_absolute_hooks_path_preserves_prior_hook(tmp_path: Path):
    repo = _repo(tmp_path)
    hooks = tmp_path / "external-hooks"
    hooks.mkdir()
    old_hook = b"#!/bin/sh\necho preserved-synthetic-hook\n"
    (hooks / "pre-push").write_bytes(old_hook)
    _configure_hooks_path(repo, str(hooks))

    install_hook(repo)
    assert is_sentinel_hook(hooks / "pre-push")
    assert (hooks / "pre-push.sentinel-backup").read_bytes() == old_hook
    assert not (repo / ".git" / "hooks" / "pre-push").exists()

    uninstall_hook(repo)
    assert (hooks / "pre-push").read_bytes() == old_hook
    assert not (hooks / "pre-push.sentinel-backup").exists()


def test_non_directory_hooks_path_cannot_fall_back_to_unused_hook(tmp_path: Path):
    repo = _repo(tmp_path)
    blocker = tmp_path / "invalid-hooks-target"
    blocker.write_text("synthetic fixture\n", encoding="utf-8")
    _configure_hooks_path(repo, str(blocker))

    with pytest.raises(HookInstallError):
        install_hook(repo)
    assert blocker.read_text(encoding="utf-8") == "synthetic fixture\n"
    assert not (repo / ".git" / "hooks" / "pre-push").exists()


def test_unconfigured_repo_still_installs_and_removes_default_hook(tmp_path: Path):
    repo = _repo(tmp_path)
    install_hook(repo)
    hook = repo / ".git" / "hooks" / "pre-push"
    assert is_sentinel_hook(hook)
    uninstall_hook(repo)
    assert not hook.exists()
