# sentinel:skip-file — a synthetic unsafe eval is the BLOCK this test relies on.
"""A pushed repository must not be able to replace the scanner.

The hook runs in the repository root. `python -m sentinel` puts the current
directory first on sys.path, so a `sentinel/` directory in the repository would
run instead of the real scanner, and one that prints a clean verdict line
satisfies the hook's proof-of-run check. `python -P` omits that entry.

Real local pushes to a temporary bare repository; no network.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from sentinel.hook.installer import install_hook

FAKE_MAIN = 'print("[Sentinel] verdicts: BLOCK=0 WARN=0 INFO=0")\n'


def _git(*args: str, env: dict[str, str] | None = None):
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=120, env=env, check=False,
    )


def _repo_with_shadow(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    repo = tmp_path / "repo"
    remote = tmp_path / "remote.git"
    assert _git("init", "--bare", "-q", "-b", "main", str(remote)).returncode == 0
    assert _git("init", "-q", "-b", "main", str(repo)).returncode == 0
    assert _git("-C", str(repo), "config", "user.email", "tester@example.invalid").returncode == 0
    assert _git("-C", str(repo), "config", "user.name", "Synthetic Tester").returncode == 0
    assert _git("-C", str(repo), "remote", "add", "origin", str(remote)).returncode == 0
    package = repo / "sentinel"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "__main__.py").write_text(FAKE_MAIN, encoding="utf-8")
    (repo / "clean.py").write_text("VALUE = 1\n", encoding="utf-8")
    install_hook(repo)
    assert _git("-C", str(repo), "add", "--all").returncode == 0
    assert _git("-C", str(repo), "commit", "-qm", "synthetic baseline").returncode == 0
    env = os.environ.copy()
    root = str(Path(__file__).parents[2])
    env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
    return repo, env


def test_repository_sentinel_package_does_not_replace_the_scanner(tmp_path: Path) -> None:
    repo, env = _repo_with_shadow(tmp_path)
    (repo / "unsafe.py").write_text("result = eval(user_input)\n", encoding="utf-8")
    assert _git("-C", str(repo), "add", "unsafe.py").returncode == 0
    assert _git("-C", str(repo), "commit", "-qm", "synthetic blocked candidate").returncode == 0

    push = _git("-C", str(repo), "push", "-u", "origin", "main", env=env)
    output = push.stdout + push.stderr
    assert push.returncode != 0, output
    assert "P0-unsafe-eval-exec" in output, output


def test_clean_repository_with_a_sentinel_package_still_pushes(tmp_path: Path) -> None:
    repo, env = _repo_with_shadow(tmp_path)
    push = _git("-C", str(repo), "push", "-u", "origin", "main", env=env)
    output = push.stdout + push.stderr
    assert push.returncode == 0, output
    assert "[Sentinel] scope:" in output, "the real scanner must have run"
