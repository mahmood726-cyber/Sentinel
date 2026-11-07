"""A linked Git worktree must be scanned, not rejected as a non-repository.

All fixtures are synthetic. Both a clean worktree and a genuine BLOCK
exercise the scanner entry point; a fake .git marker cannot earn a clean pass.
"""
from __future__ import annotations

from argparse import Namespace
from pathlib import Path
import subprocess

from sentinel.cli.scan import _run


def _linked_worktree(tmp_path: Path) -> Path:
    primary = tmp_path / "primary"
    primary.mkdir()
    subprocess.run(["git", "init", "-q", str(primary)], check=True)
    (primary / "hello.py").write_text(
        "def hello():\n    return 'synthetic'\n", encoding="utf-8"
    )
    subprocess.run(["git", "-C", str(primary), "add", "."], check=True)
    subprocess.run(
        [
            "git", "-C", str(primary),
            "-c", "user.name=Synthetic Fixture",
            "-c", "user.email=fixture@example.invalid",
            "commit", "-q", "-m", "synthetic baseline",
        ],
        check=True,
    )
    linked = tmp_path / "linked"
    subprocess.run(
        ["git", "-C", str(primary), "worktree", "add", "-q",
         "--detach", str(linked), "HEAD"],
        check=True,
    )
    assert (linked / ".git").is_file()
    return linked


def _scan(repo: Path) -> int:
    return _run(Namespace(
        repo=repo, project_index=repo, diff=False, base_ref="HEAD",
        json=False, sarif=False, timing=False,
    ))


def test_clean_linked_worktree_is_scannable(tmp_path: Path, capsys):
    linked = _linked_worktree(tmp_path)
    assert _scan(linked) == 0
    out = capsys.readouterr()
    assert "[Sentinel] verdicts: BLOCK=0" in out.out


def test_linked_worktree_block_is_not_skipped(tmp_path: Path, capsys):
    linked = _linked_worktree(tmp_path)
    (linked / "cert.json").write_text(
        '{"sig":"SIG_RSA_SHA256_synthetic"}\n', encoding="utf-8"
    )
    subprocess.run(["git", "-C", str(linked), "add", "cert.json"], check=True)
    assert _scan(linked) == 1
    out = capsys.readouterr()
    assert "P0-placeholder-hmac" in out.out


def test_fake_git_file_cannot_get_clean_verdict(tmp_path: Path, capsys):
    fake = tmp_path / "not-a-repo"
    fake.mkdir()
    (fake / ".git").write_text("not a gitdir pointer\n", encoding="utf-8")
    assert _scan(fake) != 0
    out = capsys.readouterr()
    assert "verdicts: BLOCK=0" not in out.out
