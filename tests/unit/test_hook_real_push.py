# sentinel:skip-file — a synthetic invalid eval expression is asserted as a BLOCK.
"""Exercise the installed hook with a real local git push, not a mocked scanner.

The remote is a temporary bare repository on disk; no network or publications.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

from sentinel.hook.installer import install_hook, is_sentinel_hook


def _run_git(*args: str, timeout: int = 45, env: dict[str, str] | None = None):
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=timeout, env=env, check=False,
    )


def test_actual_push_runs_custom_hooks_path_after_atomic_reinstall(tmp_path: Path):
    repo = tmp_path / "repo"
    remote = tmp_path / "remote.git"
    assert _run_git("init", "--bare", "-q", "-b", "main", str(remote)).returncode == 0
    assert _run_git("init", "-q", "-b", "main", str(repo)).returncode == 0
    assert _run_git("-C", str(repo), "config", "user.email", "tester@example.invalid").returncode == 0
    assert _run_git("-C", str(repo), "config", "user.name", "Synthetic Tester").returncode == 0
    assert _run_git("-C", str(repo), "config", "core.hooksPath", "managed-hooks").returncode == 0
    assert _run_git("-C", str(repo), "remote", "add", "origin", str(remote)).returncode == 0

    (repo / "clean.py").write_text("VALUE = 1\n", encoding="utf-8")
    install_hook(repo)
    hook = repo / "managed-hooks" / "pre-push"
    assert is_sentinel_hook(hook)
    assert not (repo / ".git" / "hooks" / "pre-push").exists()
    assert _run_git("-C", str(repo), "add", "--all").returncode == 0
    assert _run_git("-C", str(repo), "commit", "-qm", "synthetic clean baseline").returncode == 0

    env = os.environ.copy()
    root = str(Path(__file__).parents[2])
    env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
    clean_push = _run_git("-C", str(repo), "push", "-u", "origin", "main", env=env)
    assert clean_push.returncode == 0, clean_push.stdout + clean_push.stderr

    # Reinstall exercises the atomic replacement path before the BLOCK check.
    install_hook(repo)
    assert is_sentinel_hook(hook)
    (repo / "unsafe.py").write_text("result = eval(user_input)\n", encoding="utf-8")
    assert _run_git("-C", str(repo), "add", "unsafe.py").returncode == 0
    assert _run_git("-C", str(repo), "commit", "-qm", "synthetic blocked candidate").returncode == 0
    blocked_push = _run_git("-C", str(repo), "push", "origin", "main", env=env)
    output = blocked_push.stdout + blocked_push.stderr
    assert blocked_push.returncode != 0, output
    assert "P0-unsafe-eval-exec" in output, output
    assert "[Sentinel] verdicts:" in output, output
    assert _run_git("-C", str(remote), "rev-parse", "refs/heads/main").stdout.strip() != (
        _run_git("-C", str(repo), "rev-parse", "HEAD").stdout.strip()
    )
