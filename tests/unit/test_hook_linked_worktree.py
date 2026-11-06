"""Linked worktree hook installation must agree with scan's Git layout support.

Synthetic Git fixtures only. Linked worktrees share their primary repository's
default hooks directory; a pre-existing hook must survive install/uninstall.
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


def _linked_worktree(tmp_path: Path) -> tuple[Path, Path]:
    primary = tmp_path / "primary"
    primary.mkdir()
    subprocess.run(["git", "init", "-q", str(primary)], check=True)
    (primary / "valid.py").write_text("value = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(primary), "add", "valid.py"], check=True)
    subprocess.run(
        ["git", "-C", str(primary),
         "-c", "user.name=Synthetic Fixture",
         "-c", "user.email=fixture@example.invalid",
         "commit", "-q", "-m", "synthetic initial commit"],
        check=True,
    )
    linked = tmp_path / "linked"
    subprocess.run(
        ["git", "-C", str(primary), "worktree", "add", "-q",
         "--detach", str(linked), "HEAD"],
        check=True,
    )
    assert (linked / ".git").is_file()
    return primary, linked


def test_linked_worktree_install_preserves_and_restores_existing_hook(tmp_path: Path):
    primary, linked = _linked_worktree(tmp_path)
    hooks = primary / ".git" / "hooks"
    original = b"#!/bin/sh\necho synthetic-original\n"
    (hooks / "pre-push").write_bytes(original)

    install_hook(linked)
    assert is_sentinel_hook(hooks / "pre-push")
    assert (hooks / "pre-push.sentinel-backup").read_bytes() == original
    assert (linked / ".gitignore").exists()
    assert not (primary / ".gitignore").exists()

    install_hook(linked)
    assert (hooks / "pre-push.sentinel-backup").read_bytes() == original

    uninstall_hook(linked)
    assert (hooks / "pre-push").read_bytes() == original
    assert not (hooks / "pre-push.sentinel-backup").exists()


def test_linked_worktree_install_default_block_and_remove(tmp_path: Path):
    primary, linked = _linked_worktree(tmp_path)
    hook = primary / ".git" / "hooks" / "pre-push"
    assert not hook.exists()
    install_hook(linked)
    assert is_sentinel_hook(hook)
    assert 'MODE="${SENTINEL_MODE:-block}"' in hook.read_text(encoding="utf-8")
    uninstall_hook(linked)
    assert not hook.exists()


def test_malformed_gitfile_is_rejected_without_mutation(tmp_path: Path):
    fake = tmp_path / "not-git"
    fake.mkdir()
    marker = fake / ".git"
    marker.write_text("gitdir: /nonexistent/synthetic/gitdir\n", encoding="utf-8")
    with pytest.raises(HookInstallError):
        install_hook(fake)
    assert marker.is_file()
    assert not (fake / ".gitignore").exists()
    assert not (fake / "hooks").exists()
    with pytest.raises(HookInstallError):
        uninstall_hook(fake)
    assert marker.is_file()
