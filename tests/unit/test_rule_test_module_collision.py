"""Tests for P1-test-module-collision.

Fires when two `test_*.py` files share a basename across directories
AND at least one parent directory lacks `__init__.py`. Past incident:
lessons.md "Module-name collision hides tests" (AlMizan 9 → 39 visible
tests after adding tests/__init__.py).
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "test_module_collision.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def test_severity_is_block(tmp_path):
    """Block — failure is silent (pytest collects without error; tests
    just don't run)."""
    assert _rule().severity == Severity.BLOCK


def test_fires_on_root_and_subdir_collision(tmp_path):
    """The AlMizan shape: test_foo.py at root + tests/test_foo.py with no
    __init__.py."""
    (tmp_path / "test_foo.py").write_text("# top\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_foo.py").write_text("# nested\n", encoding="utf-8")
    verdicts = _rule().check(_ctx(tmp_path))
    # One verdict per offending file (both lack __init__.py).
    assert len(verdicts) >= 2
    files = {v.file for v in verdicts}
    assert "test_foo.py" in files
    assert "tests/test_foo.py" in files


def test_quiet_when_init_present(tmp_path):
    """Adding __init__.py to BOTH dirs makes the second path
    `tests.test_foo` — distinct module, no collision."""
    (tmp_path / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "test_foo.py").write_text("# top\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "tests" / "test_foo.py").write_text("# nested\n", encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_unique_basenames(tmp_path):
    """Different basenames in different dirs — no collision."""
    (tmp_path / "test_foo.py").write_text("# x\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_bar.py").write_text("# y\n", encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_single_occurrence(tmp_path):
    """A single test_foo.py with no sibling is fine even without __init__.py."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_foo.py").write_text("# only one\n", encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []
