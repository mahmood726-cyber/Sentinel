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
import subprocess
from pathlib import Path

from sentinel.hook.payload import HOOK_SCRIPT, SENTINEL_MARKER, make_hook_script
from sentinel.io.paths import OUTPUT_FILENAMES, LEGACY_FILENAMES


class HookInstallError(Exception):
    """Raised when install/uninstall cannot proceed safely."""


GITIGNORE_MARKER = "# === Sentinel hook output (auto-added by install) ==="


def _hooks_dir(repo_root: Path) -> Path:
    """Resolve the *active* Git hook directory for regular and linked worktrees.

    Git's core.hooksPath overrides .git/hooks, even for a normal checkout.
    Always ask Git rather than assuming that the on-disk .git directory is
    the active hooks location. Keep the old minimal .git-directory fixture
    support used by tests which do not create a complete Git repository.
    """
    git_marker = repo_root / ".git"
    if not git_marker.is_dir() and not git_marker.is_file():
        raise HookInstallError(f"not a git repository: {repo_root}")

    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--git-path", "hooks"],
            capture_output=True, text=True, encoding="utf-8", timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        raise HookInstallError("could not resolve Git hooks directory") from None

    hooks_path = result.stdout.rstrip("\r\n")
    if result.returncode == 0 and hooks_path:
        candidate = Path(hooks_path)
        hooks_dir = candidate if candidate.is_absolute() else repo_root / candidate
    elif git_marker.is_dir() and not (git_marker / "HEAD").exists():
        # Compatibility with existing bare-minimum local test fixtures.
        hooks_dir = git_marker / "hooks"
    else:
        raise HookInstallError("could not resolve Git hooks directory")

    if hooks_dir.exists() and not hooks_dir.is_dir():
        raise HookInstallError("configured Git hooks path is not a directory")
    return hooks_dir


def is_sentinel_hook(hook_path: Path) -> bool:
    if not hook_path.is_file():
        return False
    try:
        content = hook_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return SENTINEL_MARKER in content


def ensure_sentinel_gitignored(repo_root: Path) -> None:
    """Append Sentinel's output filenames to the target repo's .gitignore.

    Without this, a user running `git add .` after a Sentinel scan can
    commit STUCK_FAILURES.md / sentinel-findings.md — which embed the
    scanned repo's absolute paths (C:\\... or /home/...), self-violating
    the P0-hardcoded-local-path rule on the next scan.

    Idempotent: detected via GITIGNORE_MARKER; won't duplicate on reinstall.
    """
    gitignore = repo_root / ".gitignore"
    try:
        existing = gitignore.read_text(encoding="utf-8") if gitignore.exists() else ""
    except OSError:
        existing = ""
    if GITIGNORE_MARKER in existing:
        return
    block = [GITIGNORE_MARKER, *OUTPUT_FILENAMES, *LEGACY_FILENAMES]
    separator = "" if existing.endswith("\n") or not existing else "\n"
    addition = separator + "\n".join(block) + "\n"
    try:
        with gitignore.open("a", encoding="utf-8") as f:
            f.write(addition)
    except OSError:
        pass


def install_hook(repo_root: Path, mode: str = "block") -> None:
    """Install the Sentinel pre-push hook.

    mode='block' (default): BLOCK verdicts abort push. Fail-safe default for
    single-repo installs (e.g. developer opting-in to protection).
    mode='warn': BLOCK verdicts recorded but push proceeds. Safer default for
    portfolio-wide rollout where false-positive triage hasn't finished.

    Also appends Sentinel's output filenames to the target repo's .gitignore
    (idempotently) to prevent users from accidentally committing findings
    that contain absolute local paths.
    """
    hooks_dir = _hooks_dir(repo_root)
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook = hooks_dir / "pre-push"
    backup = hooks_dir / "pre-push.sentinel-backup"

    if hook.exists() and not is_sentinel_hook(hook):
        if not backup.exists():
            backup.write_bytes(hook.read_bytes())
            _chmod_exec(backup)

    hook.write_text(make_hook_script(mode), encoding="utf-8")
    _chmod_exec(hook)
    ensure_sentinel_gitignored(repo_root)


def uninstall_hook(repo_root: Path) -> None:
    hooks_dir = _hooks_dir(repo_root)
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
