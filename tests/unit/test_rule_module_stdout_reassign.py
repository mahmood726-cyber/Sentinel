"""Tests for P1-module-stdout-reassign.

Fires on module-level `sys.stdout = io.TextIOWrapper(...)` that doesn't
exclude pytest. Past incident: lessons.md "Module-level sys.stdout
reassignment kills pytest capture".
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "module_stdout_reassign.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def test_severity_is_warn(tmp_path):
    assert _rule().severity == Severity.WARN


def test_fires_on_unguarded_reassign(tmp_path):
    (tmp_path / "bad.py").write_text(
        "import sys\nimport io\n\n"
        'if sys.platform == "win32":\n'
        '    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")\n',
        encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert verdicts[0].file == "bad.py"


def test_quiet_when_pytest_excluded(tmp_path):
    (tmp_path / "good.py").write_text(
        "import sys\nimport io\n\n"
        'if sys.platform == "win32" and "pytest" not in sys.modules:\n'
        '    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")\n',
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_inside_function(tmp_path):
    """Reassignment inside a function (called from main) is safe — pytest
    imports the module but doesn't invoke main()."""
    (tmp_path / "good.py").write_text(
        "import sys\nimport io\n\n"
        "def main():\n"
        '    if sys.platform == "win32":\n'
        '        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")\n',
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_under_main_guard(tmp_path):
    """if __name__ == '__main__' wrapping protects from pytest."""
    (tmp_path / "good.py").write_text(
        "import sys\nimport io\n\n"
        'if __name__ == "__main__":\n'
        '    if sys.platform == "win32":\n'
        '        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")\n',
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_skip_file_marker_honored(tmp_path):
    (tmp_path / "skipped.py").write_text(
        "# sentinel:skip-file\n"
        "import sys, io\n"
        'if sys.platform == "win32":\n'
        '    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")\n',
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []
