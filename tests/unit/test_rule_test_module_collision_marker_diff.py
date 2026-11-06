"""Deleted package markers must not hide test-module collisions in --diff scans.

All files are deterministic synthetic fixtures; no third-party publications.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.io.git_files import set_path_filter
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "test_module_collision.py"
)


def _seed(root: Path, *, north_marker: bool, unrelated_marker: bool = False) -> None:
    for side in ("north", "south"):
        inner = root / side / "sub"
        inner.mkdir(parents=True)
        (inner / "__init__.py").write_text("", encoding="utf-8")
        (inner / "test_shared.py").write_text(
            "def test_synthetic():\n    assert True\n", encoding="utf-8"
        )
    if north_marker:
        (root / "north" / "__init__.py").write_text("", encoding="utf-8")
    if unrelated_marker:
        extra = root / "unrelated"
        extra.mkdir()
        (extra / "__init__.py").write_text("", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Synthetic Fixture",
         "-c", "user.email=fixture@example.invalid",
         "commit", "-q", "-m", "synthetic baseline"],
        cwd=root, check=True,
    )


def _check(root: Path, changed: set[str]):
    set_path_filter(frozenset(changed))
    try:
        return load_plugin_rule(PLUGIN_PATH).check(
            RepoContext(repo_root=root, mode=ScanMode.REPO)
        )
    finally:
        set_path_filter(None)


def test_deleting_only_ancestor_init_must_block_new_import_collision(tmp_path: Path):
    """A staged package-marker deletion changes imports without editing tests."""
    _seed(tmp_path, north_marker=True)
    assert _check(tmp_path, {"north/sub/test_shared.py"}) == []

    subprocess.run(
        ["git", "rm", "-q", "north/__init__.py"], cwd=tmp_path, check=True
    )
    findings = _check(tmp_path, {"north/__init__.py"})
    assert {v.file for v in findings} == {"north/__init__.py"}
    assert all(v.severity == Severity.BLOCK for v in findings)
    assert "north/sub/test_shared.py" in findings[0].detail
    assert "south/sub/test_shared.py" in findings[0].detail


def test_deleting_unrelated_marker_does_not_report_historical_collision(
    tmp_path: Path,
):
    """A different existing collision must not block unrelated marker removal."""
    _seed(tmp_path, north_marker=False, unrelated_marker=True)
    subprocess.run(
        ["git", "rm", "-q", "unrelated/__init__.py"], cwd=tmp_path, check=True
    )
    assert _check(tmp_path, {"unrelated/__init__.py"}) == []


def test_adding_marker_resolving_collision_stays_clean(tmp_path: Path):
    """A tracked added package marker is not a deleted-marker BLOCK."""
    _seed(tmp_path, north_marker=False)
    (tmp_path / "north" / "__init__.py").write_text("", encoding="utf-8")
    subprocess.run(
        ["git", "add", "north/__init__.py"], cwd=tmp_path, check=True
    )
    assert _check(tmp_path, {"north/__init__.py"}) == []


def test_editing_existing_marker_cannot_block_historical_collision(tmp_path: Path):
    """Content-only changes of a tracked marker do not change import identity."""
    _seed(tmp_path, north_marker=False, unrelated_marker=True)
    (tmp_path / "unrelated" / "__init__.py").write_text(
        "# harmless\n", encoding="utf-8"
    )
    assert _check(tmp_path, {"unrelated/__init__.py"}) == []
