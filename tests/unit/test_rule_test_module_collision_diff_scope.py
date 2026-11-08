"""Differential candidate scope must retain unchanged tracked test context.

All fixtures are deterministic and synthetic. No publication content.
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


def _seed_repo(root: Path, *, packaged: bool = False) -> None:
    for directory in ("north", "south"):
        path = root / directory
        path.mkdir()
        (path / "test_shared.py").write_text(
            "def test_synthetic():\n    assert True\n", encoding="utf-8"
        )
        if packaged:
            (path / "__init__.py").write_text("", encoding="utf-8")
    (root / "README.md").write_text("synthetic fixture\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)


def _scan_diff(root: Path, changed: set[str]):
    set_path_filter(frozenset(changed))
    try:
        return load_plugin_rule(PLUGIN_PATH).check(
            RepoContext(repo_root=root, mode=ScanMode.REPO)
        )
    finally:
        set_path_filter(None)


def test_diff_one_colliding_test_must_block(tmp_path: Path):
    """An unchanged tracked test is necessary context for a changed module."""
    _seed_repo(tmp_path)
    findings = _scan_diff(tmp_path, {"north/test_shared.py"})
    assert {v.file for v in findings} == {"north/test_shared.py"}
    assert all(v.severity == Severity.BLOCK for v in findings)


def test_diff_unrelated_change_stays_clean(tmp_path: Path):
    """Historical collisions must not block an unrelated clean push."""
    _seed_repo(tmp_path)
    assert _scan_diff(tmp_path, {"README.md"}) == []


def test_diff_two_colliding_tests_reports_both(tmp_path: Path):
    _seed_repo(tmp_path)
    findings = _scan_diff(
        tmp_path, {"north/test_shared.py", "south/test_shared.py"}
    )
    assert {v.file for v in findings} == {
        "north/test_shared.py", "south/test_shared.py"
    }


def test_diff_one_packaged_test_stays_clean(tmp_path: Path):
    """Unchanged tracked __init__.py markers must remain in scope as context."""
    _seed_repo(tmp_path, packaged=True)
    assert _scan_diff(tmp_path, {"north/test_shared.py"}) == []
