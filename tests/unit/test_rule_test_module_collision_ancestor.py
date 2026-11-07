"""Regression for nested pytest package markers (synthetic Git fixtures only)."""
from __future__ import annotations

import subprocess
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule

PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "test_module_collision.py"
)


def _scan(tmp_path: Path):
    return load_plugin_rule(PLUGIN_PATH).check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )


def _git_stage(repo: Path):
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)


def _test_tree(tmp_path: Path, *, track_ancestors: bool, distinct_inners: bool = False):
    for outer, name in (("north", "sub_north" if distinct_inners else "sub"),
                        ("south", "sub_south" if distinct_inners else "sub")):
        root_pkg = tmp_path / outer
        leaf = root_pkg / name
        leaf.mkdir(parents=True)
        if track_ancestors:
            (root_pkg / "__init__.py").write_text("", encoding="utf-8")
        (leaf / "__init__.py").write_text("", encoding="utf-8")
        (leaf / "test_example.py").write_text(
            "def test_synthetic():\n    assert True\n", encoding="utf-8"
        )
    _git_stage(tmp_path)


def test_missing_ancestor_markers_cannot_hide_same_import_name(tmp_path: Path):
    _test_tree(tmp_path, track_ancestors=False)
    findings = _scan(tmp_path)
    assert {v.file for v in findings} == {
        "north/sub/test_example.py", "south/sub/test_example.py"
    }
    assert all(v.severity == Severity.BLOCK for v in findings)


def test_complete_tracked_ancestor_markers_are_clean(tmp_path: Path):
    _test_tree(tmp_path, track_ancestors=True)
    assert _scan(tmp_path) == []


def test_distinct_partial_package_names_are_clean(tmp_path: Path):
    _test_tree(tmp_path, track_ancestors=False, distinct_inners=True)
    assert _scan(tmp_path) == []
