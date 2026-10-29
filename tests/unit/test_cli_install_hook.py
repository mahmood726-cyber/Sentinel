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
    hook = repo / ".git" / "hooks" / "pre-push"
    assert hook.exists()
    assert 'MODE="${SENTINEL_MODE:-block}"' in hook.read_text(encoding="utf-8")
    assert "mode=block" in res.stdout


def test_install_hook_cli_warn_requires_explicit_option(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    res = _run("install-hook", "--repo", str(repo), "--mode", "warn")
    assert res.returncode == 0, f"stderr: {res.stderr}"
    hook = repo / ".git" / "hooks" / "pre-push"
    assert 'MODE="${SENTINEL_MODE:-warn}"' in hook.read_text(encoding="utf-8")
    assert "mode=warn" in res.stdout


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

def test_install_hook_cli_rejects_unsupported_mode_without_mutation(tmp_path: Path):
    """An unsupported soft/off mode must not weaken an installed BLOCK hook."""
    repo = _make_git_repo(tmp_path)
    installed = _run("install-hook", "--repo", str(repo))
    assert installed.returncode == 0, installed.stderr
    hook = repo / ".git" / "hooks" / "pre-push"
    original = hook.read_bytes()

    attempted = _run("install-hook", "--repo", str(repo), "--mode", "off")
    assert attempted.returncode != 0
    assert "invalid choice" in attempted.stderr
    assert hook.read_bytes() == original
    assert 'MODE="${SENTINEL_MODE:-block}"' in hook.read_text(encoding="utf-8")


def test_default_cli_hook_preserves_fail_closed_bypass_guards(tmp_path: Path):
    """Default BLOCK mode must retain scan-crash and discard-log refusals.

    This is a generated-hook contract check, not a substitute for a real
    pre-push integration test on both operating systems.
    """
    repo = _make_git_repo(tmp_path)
    installed = _run("install-hook", "--repo", str(repo))
    assert installed.returncode == 0, installed.stderr
    script = (repo / ".git" / "hooks" / "pre-push").read_text(encoding="utf-8")
    assert 'MODE="${SENTINEL_MODE:-block}"' in script
    assert 'if [ "${SENTINEL_BYPASS:-0}" = "1" ]; then' in script
    assert 'case "$log_path" in' in script
    assert "SENTINEL_BYPASS_LOG resolves to a discard target" in script
    assert "failed to append to bypass log" in script
    assert "scan did NOT produce verdicts" in script
    assert "scan returned internal-error" in script
    assert 'if [ "$MODE" = "warn" ] && [ "$rc" = "1" ]; then' in script
    assert 'if [ $rc -ne 0 ]; then' in script
