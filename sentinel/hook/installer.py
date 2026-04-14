"""Git pre-push hook installer.

Contracts (see M1 design spec):
- Idempotent: running install twice = running once.
- Chaining: if a pre-push hook exists, Sentinel saves it as
  `pre-push.sentinel-backup` and invokes it on exit 0.
- Never clobbers the user's original hook: uninstall restores from backup.
"""
from __future__ import annotations
import os
import stat
from pathlib import Path

from sentinel.hook.payload import HOOK_SCRIPT, SENTINEL_MARKER, make_hook_script


class HookInstallError(Exception):
    """Raised when install/uninstall cannot proceed safely."""


def is_sentinel_hook(hook_path: Path) -> bool:
    if not hook_path.is_file():
        return False
    try:
        content = hook_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return SENTINEL_MARKER in content


def install_hook(repo_root: Path, mode: str = "block") -> None:
    """Install the Sentinel pre-push hook.

    mode='block' (default): BLOCK verdicts abort push. Fail-safe default for
    single-repo installs (e.g. developer opting-in to protection).
    mode='warn': BLOCK verdicts recorded but push proceeds. Safer default for
    portfolio-wide rollout where false-positive triage hasn't finished.
    """
    git_dir = repo_root / ".git"
    if not git_dir.is_dir():
        raise HookInstallError(f"not a git repository: {repo_root}")
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook = hooks_dir / "pre-push"
    backup = hooks_dir / "pre-push.sentinel-backup"

    if hook.exists() and not is_sentinel_hook(hook):
        if not backup.exists():
            backup.write_bytes(hook.read_bytes())
            _chmod_exec(backup)

    hook.write_text(make_hook_script(mode), encoding="utf-8")
    _chmod_exec(hook)


def uninstall_hook(repo_root: Path) -> None:
    hooks_dir = repo_root / ".git" / "hooks"
    hook = hooks_dir / "pre-push"
    backup = hooks_dir / "pre-push.sentinel-backup"
    if backup.exists():
        hook.write_bytes(backup.read_bytes())
        _chmod_exec(hook)
        backup.unlink()
    elif hook.exists() and is_sentinel_hook(hook):
        hook.unlink()


def _chmod_exec(path: Path) -> None:
    try:
        current = path.stat().st_mode
        path.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass
