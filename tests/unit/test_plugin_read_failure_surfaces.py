"""BLOCK plugins must not treat an unreadable candidate as a clean one.

Each rule below swallowed OSError and moved on, so a file that could not be
read produced no finding and the scan reported clean. As for the plugins
already fixed in this series, the failure now reaches the scanner's fatal
contract (exit 10): an ordinary BLOCK would be downgraded by a warn-mode hook.
"""
from __future__ import annotations

import json
import subprocess
import traceback
from pathlib import Path

import pytest

from sentinel.core import RepoContext, ScanMode
from sentinel.io.git_files import (
    GitFileEnumerationError,
    iter_repo_files,
    iter_tree_or_filter,
    set_path_filter,
)
from sentinel.registry.plugin_loader import load_plugin_rule

PLUGINS = Path(__file__).parents[2] / "sentinel" / "rules" / "plugins"
PRIVATE = "PRIVATE_SYNTHETIC_PATH_MUST_NOT_LEAK"

CASES = [
    ("aact_snapshot_provenance.py", "trial-capsule.html"),
    ("citation_cascade.py", "paper.md"),
    ("citation_resolution.py", "paper.md"),
    ("denominator_logic.py", "A_REVIEW.html"),
    ("localstorage_key_collision.py", "A_REVIEW.html"),
    ("rapidmeta_data_integrity.py", "A_REVIEW.html"),
]
IDS = [c[0].removesuffix(".py") for c in CASES]


def _scan(plugin: str, root: Path):
    rule = load_plugin_rule(PLUGINS / plugin)
    return rule.check(RepoContext(repo_root=root, mode=ScanMode.REPO))


def _setup(root: Path, plugin: str, candidate: str) -> Path:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    if plugin == "citation_resolution.py":
        # That rule reads no candidate until the cache lists something.
        (root / "doi-cache.json").write_text(
            json.dumps({"10.1000/synthetic": {"status": "unresolved"}}), encoding="utf-8",
        )
    path = root / candidate
    path.write_text("<html>synthetic clean content</html>\n", encoding="utf-8")
    return path


def _deny(monkeypatch, method: str, target: Path) -> None:
    original = getattr(Path, method)

    def denied(self, *args, **kwargs):
        if self == target:
            raise PermissionError(PRIVATE)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, method, denied)


# aact_snapshot_provenance has no size check, so it never calls stat().
FAILURES = [(c, "read_text") for c in CASES] + [
    (c, "stat") for c in CASES if c[0] != "aact_snapshot_provenance.py"
]


@pytest.mark.parametrize(
    ("case", "method"), FAILURES, ids=[f"{c[0][:-3]}-{m}" for c, m in FAILURES],
)
def test_unreadable_candidate_aborts_the_scan(
    tmp_path: Path, monkeypatch, case: tuple[str, str], method: str,
) -> None:
    plugin, candidate = case
    target = _setup(tmp_path, plugin, candidate)
    _deny(monkeypatch, method, target)
    with pytest.raises(GitFileEnumerationError) as exc:
        _scan(plugin, tmp_path)
    rendered = "".join(traceback.format_exception(exc.value))
    assert PRIVATE not in rendered


@pytest.mark.parametrize(("plugin", "candidate"), CASES, ids=IDS)
def test_readable_candidate_stays_clean(tmp_path: Path, plugin: str, candidate: str) -> None:
    _setup(tmp_path, plugin, candidate)
    assert _scan(plugin, tmp_path) == []


def test_unreadable_doi_cache_aborts_instead_of_disabling_the_rule(
    tmp_path: Path, monkeypatch,
) -> None:
    """An unreadable cache used to read as "nothing unresolved"."""
    plugin = "citation_resolution.py"
    _setup(tmp_path, plugin, "paper.md")
    _deny(monkeypatch, "read_text", tmp_path / "doi-cache.json")
    with pytest.raises(GitFileEnumerationError) as exc:
        _scan(plugin, tmp_path)
    assert PRIVATE not in "".join(traceback.format_exception(exc.value))


def test_absent_doi_cache_stays_clean(tmp_path: Path) -> None:
    (tmp_path / "paper.md").write_text("synthetic\n", encoding="utf-8")
    assert _scan("citation_resolution.py", tmp_path) == []


def test_denied_stat_does_not_read_as_a_deleted_file(tmp_path: Path, monkeypatch) -> None:
    """Path.is_file() answers False on OSError, so without an explicit stat a
    tracked candidate left the scan silently and rules reported clean."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    target = tmp_path / "tracked.py"
    target.write_text("value = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "tracked.py"], check=True)
    _deny(monkeypatch, "stat", target)
    with pytest.raises(GitFileEnumerationError):
        list(iter_repo_files(tmp_path, "*.py"))


def test_file_deleted_from_the_worktree_is_still_skipped(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    target = tmp_path / "tracked.py"
    target.write_text("value = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "tracked.py"], check=True)
    target.unlink()
    assert list(iter_repo_files(tmp_path, "*.py")) == []


def test_tree_filter_surfaces_a_stat_failure(tmp_path: Path, monkeypatch) -> None:
    """citation_cascade and three other rules discover through this helper."""
    target = tmp_path / "paper.md"
    target.write_text("synthetic\n", encoding="utf-8")
    _deny(monkeypatch, "is_file", target)
    set_path_filter(frozenset({"paper.md"}))
    try:
        with pytest.raises(GitFileEnumerationError) as exc:
            list(iter_tree_or_filter(tmp_path))
    finally:
        set_path_filter(None)
    assert PRIVATE not in "".join(traceback.format_exception(exc.value))
