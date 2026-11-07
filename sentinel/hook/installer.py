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
import tempfile
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
    """Only recognize scripts we actually generated, not a copied banner."""
    if not hook_path.is_file():
        return False
    try:
        content = hook_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False
    return content in (HOOK_SCRIPT, make_hook_script("warn"))


def _reject_unrecognized_marker(hook_path: Path) -> None:
    """Do not overwrite/delete a modified or marker-bearing third-party hook.

    The banner is documentation, not proof that the complete hook is ours.
    Unknown versions also require explicit human reconciliation; chaining an
    edited Sentinel script can recurse through its own backup indefinitely.
    """
    if not hook_path.exists():
        return
    try:
        content = hook_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise HookInstallError("cannot inspect existing pre-push hook") from None
    if SENTINEL_MARKER in content and content not in (
        HOOK_SCRIPT, make_hook_script("warn")
    ):
        raise HookInstallError(
            "unrecognized or modified pre-push hook with Sentinel marker; "
            "refusing to overwrite or remove it"
        )


def _reject_symlink_entries(hook: Path, backup: Path) -> None:
    """Never follow hook/backup symlinks while installing or uninstalling.

    Writing a symlinked pre-push hook can overwrite an unrelated external
    script; a symlinked backup can also redirect restoration or reads.
    Check the directory entries themselves, including dangling links.
    """
    for path in (hook, backup):
        try:
            linked = path.is_symlink()
        except OSError:
            raise HookInstallError("cannot inspect hook entry type") from None
        if linked:
            raise HookInstallError(
                "symbolic link in pre-push hook or Sentinel backup; "
                "refusing operation until explicitly reconciled"
            )


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


def _replace_hook_atomically(
    hook: Path, content: bytes, *, preserve_mode: int | None = None,
) -> None:
    """Never truncate a live pre-push executable during install or restore.

    Write, flush, and mark a temporary sibling executable before the atomic
    same-directory rename. If any step fails, leave the previous hook intact
    and remove the unfinished temporary file. Do not silently ignore chmod
    failures, which could otherwise install a hook Git never executes.
    """
    fd, name = tempfile.mkstemp(prefix=".pre-push.sentinel-", dir=hook.parent)
    pending = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if preserve_mode is None:
            pending.chmod(
                pending.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )
        else:
            # A previously installed hook might deliberately have no +x.
            # Neither chaining nor uninstall should activate a disabled hook.
            pending.chmod(preserve_mode)
        os.replace(pending, hook)
    finally:
        pending.unlink(missing_ok=True)


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
    _reject_symlink_entries(hook, backup)
    _reject_unrecognized_marker(hook)

    if hook.exists() and not is_sentinel_hook(hook):
        if backup.exists():
            # A different tool/user replaced our installed hook while the
            # original remains backed up. Never erase that new hook or
            # pretend it was chained: require explicit human resolution.
            raise HookInstallError(
                "pre-push hook replaced while Sentinel backup exists; "
                "refusing to overwrite modified hook"
            )
        # Prepare the original hook backup completely before replacing the
        # active gate. A failed stage/chmod/rename must not leave a partial
        # backup or allow a new hook to be installed without a valid chain.
        try:
            _replace_hook_atomically(
                backup, hook.read_bytes(),
                preserve_mode=stat.S_IMODE(hook.stat().st_mode),
            )
        except OSError:
            raise HookInstallError(
                "cannot safely prepare existing pre-push hook backup"
            ) from None

    _replace_hook_atomically(hook, make_hook_script(mode).encode("utf-8"))
    ensure_sentinel_gitignored(repo_root)


def uninstall_hook(repo_root: Path) -> None:
    hooks_dir = _hooks_dir(repo_root)
    hook = hooks_dir / "pre-push"
    backup = hooks_dir / "pre-push.sentinel-backup"
    _reject_symlink_entries(hook, backup)
    _reject_unrecognized_marker(hook)
    if backup.exists():
        if hook.exists() and not is_sentinel_hook(hook):
            # Uninstall must not restore an old backup over a later hook
            # installed by another tool or the repository owner.
            raise HookInstallError(
                "pre-push hook replaced while Sentinel backup exists; "
                "refusing to overwrite modified hook"
            )
        _replace_hook_atomically(
            hook, backup.read_bytes(),
            preserve_mode=stat.S_IMODE(backup.stat().st_mode),
        )
        backup.unlink()
    elif hook.exists() and is_sentinel_hook(hook):
        hook.unlink()

