# sentinel:skip-file — synthetic incident fixtures intentionally contain eval calls.
"""Fail-closed and clean-code controls for the dynamic eval/exec rule."""
from __future__ import annotations

import traceback
from pathlib import Path

import pytest

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.io.git_files import GitFileEnumerationError
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parents[2] / "sentinel" / "rules" / "plugins"
    / "unsafe_eval_exec.py"
)


def _check(root: Path):
    rule = load_plugin_rule(PLUGIN_PATH)
    return rule.check(RepoContext(repo_root=root, mode=ScanMode.REPO))


def test_unreadable_dynamic_eval_candidate_aborts_instead_of_silent_pass(
    tmp_path: Path, monkeypatch,
):
    candidate = tmp_path / "source.py"
    candidate.write_text("result = eval(user_input)\n", encoding="utf-8")
    original_read = Path.read_text

    def deny_target_read(self, *args, **kwargs):
        if self == candidate:
            raise PermissionError("PRIVATE_SYNTHETIC_PATH_MUST_NOT_LEAK")
        return original_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", deny_target_read)
    with pytest.raises(GitFileEnumerationError) as exc:
        _check(tmp_path)
    diagnostic = "".join(traceback.format_exception(exc.value))
    assert "PRIVATE_SYNTHETIC_PATH_MUST_NOT_LEAK" not in diagnostic


def test_dynamic_eval_still_blocks(tmp_path: Path):
    (tmp_path / "source.py").write_text(
        "result = eval(user_input)\n", encoding="utf-8"
    )
    verdicts = _check(tmp_path)
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.BLOCK
    assert verdicts[0].rule_id == "P0-unsafe-eval-exec"


def test_literal_eval_and_excluded_unreadable_file_remain_clean(
    tmp_path: Path, monkeypatch,
):
    (tmp_path / "clean.py").write_text(
        "result = eval('2 + 2')\n", encoding="utf-8"
    )
    excluded = tmp_path / "node_modules" / "hidden.py"
    excluded.parent.mkdir()
    excluded.write_text("result = eval(user_input)\n", encoding="utf-8")
    original_read = Path.read_text

    def deny_excluded_read(self, *args, **kwargs):
        if self == excluded:
            raise PermissionError("excluded fixture intentionally inaccessible")
        return original_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", deny_excluded_read)
    assert _check(tmp_path) == []
