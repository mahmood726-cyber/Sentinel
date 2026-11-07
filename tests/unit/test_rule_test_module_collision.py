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


# Role 06 regression: Git pathspecs must discover tracked test_*.py files
# at any depth, otherwise a package-less duplicate test module is invisible.
def _stage_synthetic_files(repo: Path) -> None:
    import subprocess

    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)


def test_git_tracked_nested_duplicate_test_modules_are_blocked(tmp_path: Path):
    (tmp_path / "test_example.py").write_text(
        "def test_root():\n    assert True\n", encoding="utf-8"
    )
    nested = tmp_path / "tests"
    nested.mkdir()
    (nested / "test_example.py").write_text(
        "def test_nested():\n    assert True\n", encoding="utf-8"
    )
    _stage_synthetic_files(tmp_path)

    # Without the recursive Git pathspec, test_*.py matches only the root
    # file, so the true BLOCK collision is silently missed on real Git repos.
    findings = _rule().check(_ctx(tmp_path))
    assert {v.file for v in findings} == {
        "test_example.py", "tests/test_example.py"
    }
    assert all(v.severity == Severity.BLOCK for v in findings)


def test_git_tracked_packaged_duplicate_names_remain_clean(tmp_path: Path):
    """Tracked package markers make identical basenames distinct modules."""
    (tmp_path / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "test_example.py").write_text(
        "def test_root():\n    assert True\n", encoding="utf-8"
    )
    nested = tmp_path / "tests"
    nested.mkdir()
    (nested / "__init__.py").write_text("", encoding="utf-8")
    (nested / "test_example.py").write_text(
        "def test_nested():\n    assert True\n", encoding="utf-8"
    )
    _stage_synthetic_files(tmp_path)
    assert _rule().check(_ctx(tmp_path)) == []


def test_git_nested_test_names_respect_excluded_and_untracked_paths(
    tmp_path: Path,
):
    """Only tracked, non-excluded paths enter the rule's candidate inventory."""
    from sentinel.io.git_files import iter_repo_files

    nested = tmp_path / "tests"
    nested.mkdir()
    (nested / "test_visible.py").write_text("pass\n", encoding="utf-8")
    excluded = tmp_path / "node_modules"
    excluded.mkdir()
    (excluded / "test_vendor.py").write_text("pass\n", encoding="utf-8")
    _stage_synthetic_files(tmp_path)
    (nested / "test_untracked.py").write_text("pass\n", encoding="utf-8")

    found = {
        p.relative_to(tmp_path).as_posix()
        for p in iter_repo_files(
            tmp_path, "test_*.py", ("node_modules",)
        )
    }
    assert found == {"tests/test_visible.py"}


def test_git_untracked_package_markers_cannot_hide_collision(tmp_path: Path):
    """Untracked __init__.py files will not exist after a push.

    Both test modules are tracked, but both package markers are untracked.
    Checking only Path.is_file() falsely treats the modules as distinct.
    """
    (tmp_path / "test_duplicate.py").write_text("def test_a(): pass\n", encoding="utf-8")
    nested = tmp_path / "tests"
    nested.mkdir()
    (nested / "test_duplicate.py").write_text("def test_b(): pass\n", encoding="utf-8")
    _stage_synthetic_files(tmp_path)

    (tmp_path / "__init__.py").write_text("", encoding="utf-8")
    (nested / "__init__.py").write_text("", encoding="utf-8")

    findings = _rule().check(_ctx(tmp_path))
    assert {v.file for v in findings} == {
        "test_duplicate.py", "tests/test_duplicate.py"
    }
    assert all(v.severity == Severity.BLOCK for v in findings)


def test_git_diff_filter_keeps_tracked_package_markers_as_context(tmp_path: Path):
    """Changing test modules must not make staged package markers invisible."""
    from sentinel.io.git_files import set_path_filter

    (tmp_path / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "test_duplicate.py").write_text("def test_a(): pass\n", encoding="utf-8")
    nested = tmp_path / "tests"
    nested.mkdir()
    (nested / "__init__.py").write_text("", encoding="utf-8")
    (nested / "test_duplicate.py").write_text("def test_b(): pass\n", encoding="utf-8")
    _stage_synthetic_files(tmp_path)

    set_path_filter(frozenset({"test_duplicate.py", "tests/test_duplicate.py"}))
    try:
        assert _rule().check(_ctx(tmp_path)) == []
    finally:
        set_path_filter(None)
