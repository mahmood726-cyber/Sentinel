"""A tracked filename that is not valid UTF-8 must neither stop every push nor
vanish from the scan.

Strict decoding turned one such name into exit 10, which blocks every push of
that repository even in warn mode. Such a file cannot be read by any rule, so
it has to stay visible: not scanned, and in the denominator.

The name is planted through `git update-index`, which takes raw path bytes on
stdin, so this runs the same on Windows, where no such file can exist on disk.
"""
from __future__ import annotations

import json
import subprocess
from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest

from sentinel.cli.scan import _collect_changed_files, _run
from sentinel.io import git_files
from sentinel.io.git_files import iter_repo_files, iter_tree_or_filter, set_path_filter
from sentinel.io.paths import LEGACY_FILENAMES, OUTPUT_FILENAMES
from sentinel.io.population import Population, repo_files
from sentinel.registry.yaml_loader import _git_tracked_files, _iter_matching_files

RAW_NAME = b"caf\xe9.py"
PRINTABLE = "caf\\xe9.py"


def _git(repo: Path, *args: str, stdin: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *args], input=stdin, check=True, capture_output=True,
    ).stdout


def _commit(repo: Path, message: str, *paths: str) -> None:
    # Exact paths only: the planted name has no worktree file, so `add -A` or
    # a matching pathspec would stage its deletion.
    _git(repo, "add", "--", *paths)
    _git(repo, "-c", "user.email=t@example.com", "-c", "user.name=Test",
         "commit", "-q", "--allow-empty", "-m", message)


def _init(repo: Path) -> None:
    """A repo with one clean file. The scan's own output is ignored, as
    install-hook arranges, so it cannot enter the denominator being tested."""
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / ".gitignore").write_text(
        "\n".join((*OUTPUT_FILENAMES, *LEGACY_FILENAMES)) + "\n", encoding="utf-8",
    )
    (repo / "good.py").write_text("answer = 42\n", encoding="utf-8")
    _commit(repo, "init", ".gitignore", "good.py")


def _plant_raw_name(repo: Path) -> None:
    """Track a blob under a name that cannot be decoded as UTF-8."""
    blob = _git(repo, "hash-object", "-w", "--stdin", stdin=b"value = 1\n").decode().strip()
    _git(repo, "update-index", "-z", "--index-info",
         stdin=b"100644 " + blob.encode() + b"\t" + RAW_NAME + b"\0")
    _git(repo, "-c", "user.email=t@example.com", "-c", "user.name=Test",
         "commit", "-q", "-m", "plant raw name")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _init(tmp_path)
    _plant_raw_name(tmp_path)
    return tmp_path


def _scan(repo: Path, **overrides) -> int:
    args = dict(repo=repo, project_index=repo, diff=False, base_ref="HEAD",
                json=False, sarif=False, timing=False)
    args.update(overrides)
    return _run(Namespace(**args))


def test_fixture_really_lists_a_raw_name(repo: Path) -> None:
    assert RAW_NAME in _git(repo, "ls-files", "-z").split(b"\0")


def test_full_scan_is_clean_and_reports_the_file_as_not_scanned(repo: Path, capsys) -> None:
    rc = _scan(repo)
    out = capsys.readouterr().out
    assert rc == 0
    assert "[Sentinel] verdicts:" in out
    assert "2 of 3 files (66.7%)" in out, "the file must stay in the denominator"
    assert "NOT SCANNED" in out
    assert PRINTABLE in out


def test_diff_scan_reports_the_changed_file_as_not_scanned(repo: Path, capsys) -> None:
    rc = _scan(repo, diff=True, base_ref="HEAD~1")
    out = capsys.readouterr().out
    assert rc == 0
    assert "--diff vs HEAD~1 - 0 of 3 files" in out
    assert "NOT SCANNED" in out
    assert PRINTABLE in out


def test_diff_scan_not_touching_the_file_does_not_report_it(repo: Path, capsys) -> None:
    # The name has no worktree file, which git would report as an unstaged
    # deletion, so mark it skip-worktree to make it genuinely unchanged.
    _git(repo, "update-index", "--skip-worktree", "-z", "--stdin", stdin=RAW_NAME + b"\0")
    (repo / "other.py").write_text("other = 1\n", encoding="utf-8")
    rc = _scan(repo, diff=True, base_ref="HEAD")
    out = capsys.readouterr().out
    assert rc == 0
    assert "NOT SCANNED" not in out


def test_json_output_carries_the_not_scanned_file(repo: Path, capsys) -> None:
    """--json prints no scope line, so a verdict has to carry it."""
    rc = _scan(repo, json=True)
    verdicts = json.loads(capsys.readouterr().out)["verdicts"]
    assert rc == 0
    hits = [v for v in verdicts if v["rule_id"] == "SENTINEL-not-scanned"]
    assert [(v["severity"], v["file"]) for v in hits] == [("WARN", PRINTABLE)]


def test_finding_reaches_the_review_log(repo: Path, capsys) -> None:
    _scan(repo)
    log = (repo / "sentinel-findings.md").read_text(encoding="utf-8")
    assert "SENTINEL-not-scanned" in log
    assert PRINTABLE in log


def test_a_real_block_elsewhere_is_still_found(repo: Path, capsys) -> None:
    (repo / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    _commit(repo, "add broken", "broken.py")
    rc = _scan(repo)
    out = capsys.readouterr().out
    assert rc == 1
    assert "P1-py-parse-check" in out
    assert "NOT SCANNED" in out


def test_clean_repo_prints_no_not_scanned_line(tmp_path: Path, capsys) -> None:
    _init(tmp_path)
    assert _scan(tmp_path) == 0
    out = capsys.readouterr().out
    assert "NOT SCANNED" not in out
    assert "2 of 2 files (100%)" in out


def test_population_keeps_the_name_in_the_denominator(repo: Path) -> None:
    for population in (Population.PUBLISHED, Population.PRESENT):
        assert len(repo_files(repo, population)) == 3


def test_no_rule_iterator_yields_the_undecodable_name(repo: Path) -> None:
    assert sorted(p.name for p in iter_repo_files(repo, "*.py")) == ["good.py"]
    assert sorted(
        p.name for p in iter_repo_files(repo, "*.py", population=Population.PRESENT)
    ) == ["good.py"]
    assert sorted(p.name for p in iter_tree_or_filter(repo, population=Population.PRESENT)
                  ) == [".gitignore", "good.py"]
    tracked = _git_tracked_files(repo)
    assert len(tracked) == 3
    assert [rel for _, rel in _iter_matching_files(repo, ["**/*.py"], [], tracked)] == ["good.py"]


def test_filtered_iterators_do_not_yield_the_undecodable_name(repo: Path) -> None:
    changed = _collect_changed_files(repo, "HEAD~1")
    assert len(changed) == 1
    set_path_filter(frozenset(changed))
    try:
        assert list(iter_repo_files(repo, "*.py")) == []
        assert list(iter_tree_or_filter(repo)) == []
    finally:
        set_path_filter(None)


@pytest.mark.parametrize("failure", [PermissionError, OSError])
def test_diff_probe_os_error_forces_a_full_scan(
    tmp_path: Path, monkeypatch, capsys, failure: type[OSError],
) -> None:
    """The docstring promises None on an untrusted probe; PermissionError used
    to escape as exit 10 instead."""
    _init(tmp_path)
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    _commit(tmp_path, "add broken", "broken.py")
    real_run = subprocess.run

    def deny_diff(cmd: list[str], **kwargs: Any) -> Any:
        if "diff" in cmd:
            raise failure("synthetic")
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(git_files.subprocess, "run", deny_diff)
    assert _collect_changed_files(tmp_path, "HEAD") is None
    rc = _scan(tmp_path, diff=True, base_ref="HEAD")
    out = capsys.readouterr().out
    assert rc == 1, "the full-scan fallback must still find the committed BLOCK"
    assert "falling back to full scan" in out
    assert "scope: FULL TREE" in out
