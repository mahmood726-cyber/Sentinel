from pathlib import Path
import stat
import pytest

from sentinel.hook.installer import (
    install_hook,
    uninstall_hook,
    is_sentinel_hook,
    HookInstallError,
)


def _make_git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git" / "hooks").mkdir(parents=True)
    return repo


def test_install_hook_creates_sentinel_marker(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    install_hook(repo)
    hook = repo / ".git" / "hooks" / "pre-push"
    assert hook.exists()
    assert is_sentinel_hook(hook)


def test_install_hook_idempotent(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    install_hook(repo)
    first = (repo / ".git" / "hooks" / "pre-push").read_text(encoding="utf-8")
    install_hook(repo)
    second = (repo / ".git" / "hooks" / "pre-push").read_text(encoding="utf-8")
    assert first == second


def test_install_hook_chains_existing_hook(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-push"
    existing = "#!/bin/sh\necho existing-hook\n"
    hook.write_text(existing, encoding="utf-8")
    install_hook(repo)
    backup = repo / ".git" / "hooks" / "pre-push.sentinel-backup"
    assert backup.exists()
    assert backup.read_text(encoding="utf-8") == existing
    new = hook.read_text(encoding="utf-8")
    assert "sentinel" in new.lower()
    assert "pre-push.sentinel-backup" in new


def test_install_hook_double_install_preserves_single_backup(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-push"
    hook.write_text("#!/bin/sh\necho original\n", encoding="utf-8")
    install_hook(repo)
    install_hook(repo)
    backup = repo / ".git" / "hooks" / "pre-push.sentinel-backup"
    assert backup.read_text(encoding="utf-8") == "#!/bin/sh\necho original\n"
    # Not two levels of backup:
    assert not (repo / ".git" / "hooks" / "pre-push.sentinel-backup.sentinel-backup").exists()


def test_install_hook_raises_on_non_git_dir(tmp_path: Path):
    with pytest.raises(HookInstallError, match="not a git repository"):
        install_hook(tmp_path)


def test_uninstall_restores_backup(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-push"
    original = "#!/bin/sh\necho original\n"
    hook.write_text(original, encoding="utf-8")
    install_hook(repo)
    uninstall_hook(repo)
    assert hook.read_text(encoding="utf-8") == original
    assert not (repo / ".git" / "hooks" / "pre-push.sentinel-backup").exists()


def test_uninstall_removes_hook_when_no_backup(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    install_hook(repo)
    uninstall_hook(repo)
    assert not (repo / ".git" / "hooks" / "pre-push").exists()
