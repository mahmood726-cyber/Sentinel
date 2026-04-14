"""Non-regression: installing the hook twice leaves one Sentinel hook in
place and preserves any pre-existing hook via the backup."""
from pathlib import Path
import pytest

from sentinel.hook import install_hook, is_sentinel_hook


def _git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git" / "hooks").mkdir(parents=True)
    return repo


@pytest.mark.regression
def test_double_install_matches_single(tmp_path: Path):
    a = _git_repo(tmp_path / "a")
    b = _git_repo(tmp_path / "b")

    install_hook(a)
    install_hook(b)
    install_hook(b)  # second install on b

    hook_a = (a / ".git" / "hooks" / "pre-push").read_text(encoding="utf-8")
    hook_b = (b / ".git" / "hooks" / "pre-push").read_text(encoding="utf-8")
    assert hook_a == hook_b
    assert is_sentinel_hook(a / ".git" / "hooks" / "pre-push")
    assert is_sentinel_hook(b / ".git" / "hooks" / "pre-push")


@pytest.mark.regression
def test_double_install_with_existing_hook_preserves_one_backup(tmp_path: Path):
    repo = _git_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-push"
    hook.write_text("#!/bin/sh\necho original\n", encoding="utf-8")

    install_hook(repo)
    install_hook(repo)

    backup = repo / ".git" / "hooks" / "pre-push.sentinel-backup"
    assert backup.read_text(encoding="utf-8") == "#!/bin/sh\necho original\n"
    assert not (repo / ".git" / "hooks" / "pre-push.sentinel-backup.sentinel-backup").exists()


@pytest.mark.regression
def test_install_preserves_prior_hook_functionality(tmp_path: Path):
    """After install, the Sentinel hook references the backup so the prior
    hook is reachable (not overwritten)."""
    repo = _git_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-push"
    hook.write_text("#!/bin/sh\necho original\n", encoding="utf-8")
    install_hook(repo)
    new = hook.read_text(encoding="utf-8")
    assert "pre-push.sentinel-backup" in new
