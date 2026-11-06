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


def test_local_git_push_with_custom_hooks_path_allows_clean_and_blocks_real_issue(
    tmp_path: Path,
) -> None:
    """Exercise Git's actual hook dispatch against a local bare remote."""
    repo, _, _ = _repo(tmp_path)
    subprocess.run(
        ["git", "-C", str(repo), "symbolic-ref", "HEAD", "refs/heads/main"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Synthetic Sentinel Test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "sentinel@example.invalid"],
        check=True,
    )
    hooks = repo / "managed-hooks"
    hooks.mkdir()
    subprocess.run(
        ["git", "-C", str(repo), "config", "core.hooksPath", "managed-hooks"],
        check=True,
    )
    old_hook = hooks / "pre-push"
    old_hook.write_bytes(b"#!/bin/sh\\nexit 79\\n")
    old_hook.chmod(0o644)  # Existing user hook is intentionally disabled.

    (repo / "hello.txt").write_text("safe synthetic fixture\\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "hello.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "remote", "add", "origin", str(remote)],
        check=True,
    )
    install_hook(repo)
    assert _mode(hooks / "pre-push.sentinel-backup") == 0o644

    clean = subprocess.run(
        ["git", "-C", str(repo), "push", "--set-upstream", "origin", "main"],
        text=True, capture_output=True, timeout=60,
    )
    assert clean.returncode == 0, clean.stderr[-1500:]
    original_head = subprocess.run(
        ["git", "--git-dir", str(remote), "rev-parse", "refs/heads/main"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()

    # A truly unsafe tracked Python file must still BLOCK a subsequent push.
    (repo / "bad.py").write_text("eval (payload)\\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "bad.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "unsafe synthetic"], check=True)
    blocked = subprocess.run(
        ["git", "-C", str(repo), "push", "origin", "main"],
        text=True, capture_output=True, timeout=60,
    )
    assert blocked.returncode != 0
    assert "P0-unsafe-eval-exec" in blocked.stdout + blocked.stderr
    remote_head = subprocess.run(
        ["git", "--git-dir", str(remote), "rev-parse", "refs/heads/main"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert remote_head == original_head  # The unsafe commit was not pushed.

    uninstall_hook(repo)
    assert old_hook.read_bytes() == b"#!/bin/sh\\nexit 79\\n"
    assert _mode(old_hook) == 0o644
