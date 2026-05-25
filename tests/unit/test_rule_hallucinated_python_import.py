"""Tests for P1-hallucinated-python-import.

Fires on `from <allowlist-pkg> import <name>` where <name> isn't an
attribute of the package — the LLM-hallucinated-API shape.
Adapted from arXiv 2601.19106 (deterministic AST analysis for
hallucination detection).

Note: tests require pandas / scipy / sklearn installed in the test
runner's env (used for the reflection step). Mock-based tests would
be too lossy — the whole point of the rule is to use actual runtime
reflection on the real package.
"""
from __future__ import annotations

import pytest
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "hallucinated_python_import.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def _has(pkg: str) -> bool:
    import importlib.util
    return importlib.util.find_spec(pkg) is not None


def test_severity_is_warn(tmp_path):
    assert _rule().severity == Severity.WARN


@pytest.mark.skipif(not _has("pandas"), reason="pandas not installed in test env")
def test_fires_on_pandas_read_exel(tmp_path):
    """The canonical hallucination from the paper."""
    (tmp_path / "bad.py").write_text(
        "from pandas import read_exel\n", encoding="utf-8"
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert "read_exel" in verdicts[0].detail
    # Closest-match suggestion should point to read_excel.
    assert "read_excel" in verdicts[0].detail


@pytest.mark.skipif(not _has("pandas"), reason="pandas not installed in test env")
def test_quiet_on_legitimate_pandas_imports(tmp_path):
    (tmp_path / "good.py").write_text(
        "from pandas import read_excel, DataFrame, Series\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_relative_import(tmp_path):
    """from . import X — skip (project-local)."""
    (tmp_path / "good.py").write_text(
        "from . import sibling\nfrom .. import upper\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_non_allowlist_package(tmp_path):
    """Imports from packages not on the allowlist are skipped — we can't
    tell if it's hallucinated vs. just-not-installed-in-scan-env."""
    (tmp_path / "good.py").write_text(
        "from somenonexistentpackage import something\n", encoding="utf-8"
    )
    assert _rule().check(_ctx(tmp_path)) == []


@pytest.mark.skipif(not _has("pandas"), reason="pandas not installed in test env")
def test_quiet_inside_try_import_error(tmp_path):
    """Optional-import idiom — `try: import; except ImportError`."""
    (tmp_path / "good.py").write_text(
        "try:\n"
        "    from pandas import made_up_function\n"
        "except ImportError:\n"
        "    made_up_function = None\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_wildcard(tmp_path):
    (tmp_path / "good.py").write_text("from numpy import *\n", encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_skip_line_marker_honored(tmp_path):
    """Per-line skip marker recognised."""
    pytest.importorskip("pandas")
    (tmp_path / "good.py").write_text(
        "# sentinel:skip-line P1-hallucinated-python-import\n"
        "from pandas import not_a_real_thing\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_syntax_error_file(tmp_path):
    """Syntax errors are P1-py-parse-check's job — this rule must not crash."""
    (tmp_path / "broken.py").write_text("def foo(:\n    pass\n", encoding="utf-8")
    # Should return cleanly with no verdicts.
    assert _rule().check(_ctx(tmp_path)) == []
