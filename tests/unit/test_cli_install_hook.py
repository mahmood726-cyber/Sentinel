import subprocess
import sys
from pathlib import Path

SENTINEL_ROOT = Path(__file__).parent.parent.parent


def _make_git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git" / "hooks").mkdir(parents=True)
    return repo


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(SENTINEL_ROOT),
    )


def test_install_hook_cli_writes_hook(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    res = _run("install-hook", "--repo", str(repo))
    assert res.returncode == 0, f"stderr: {res.stderr}"
    assert (repo / ".git" / "hooks" / "pre-push").exists()


def test_install_hook_cli_non_git_errors(tmp_path: Path):
    res = _run("install-hook", "--repo", str(tmp_path))
    assert res.returncode == 1
    assert "not a git repository" in res.stderr.lower()


def test_uninstall_hook_cli_removes_hook(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    _run("install-hook", "--repo", str(repo))
    res = _run("uninstall-hook", "--repo", str(repo))
    assert res.returncode == 0
    assert not (repo / ".git" / "hooks" / "pre-push").exists()
