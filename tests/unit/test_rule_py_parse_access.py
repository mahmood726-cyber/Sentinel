# sentinel:skip-file — synthetic tests deliberately include invalid Python syntax.
"""Fail-closed and valid-code controls for Python parse candidate access."""
from __future__ import annotations

import traceback
from pathlib import Path

import pytest

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.io.git_files import GitFileEnumerationError
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parents[2] / "sentinel" / "rules" / "plugins"
    / "py_parse_check.py"
)


def _scan(root: Path):
    rule = load_plugin_rule(PLUGIN_PATH)
    return rule.check(RepoContext(repo_root=root, mode=ScanMode.REPO))


def test_unreadable_python_candidate_is_fatal_not_warn_downgradable(
    tmp_path: Path, monkeypatch,
):
    candidate = tmp_path / "source.py"
    candidate.write_text("if True print('broken')\n", encoding="utf-8")
    original_read = Path.read_text

    def deny_candidate(self, *args, **kwargs):
        if self == candidate:
            raise PermissionError("PRIVATE_SYNTHETIC_PATH_MUST_NOT_LEAK")
        return original_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", deny_candidate)
    with pytest.raises(GitFileEnumerationError) as exc:
        _scan(tmp_path)
    detail = "".join(traceback.format_exception(exc.value))
    assert "PRIVATE_SYNTHETIC_PATH_MUST_NOT_LEAK" not in detail


def test_readable_python_syntax_error_still_blocks(tmp_path: Path):
    (tmp_path / "bad.py").write_text("if True print('broken')\n", encoding="utf-8")
    (tmp_path / "good.py").write_text(
        "def ok(x: int) -> int:\n    return x + 1\n", encoding="utf-8"
    )
    verdicts = _scan(tmp_path)
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "P1-py-parse-check"
    assert verdicts[0].severity == Severity.BLOCK
    assert verdicts[0].file == "bad.py"


def test_valid_python_and_excluded_unreadable_candidate_are_clean(
    tmp_path: Path, monkeypatch,
):
    (tmp_path / "good.py").write_text("answer = 42\n", encoding="utf-8")
    excluded = tmp_path / ".venv" / "broken.py"
    excluded.parent.mkdir()
    excluded.write_text("if True print('broken')\n", encoding="utf-8")
    original_read = Path.read_text

    def deny_excluded(self, *args, **kwargs):
        if self == excluded:
            raise PermissionError("excluded synthetic fixture")
        return original_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", deny_excluded)
    assert _scan(tmp_path) == []
