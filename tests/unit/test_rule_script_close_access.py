# sentinel:skip-file — synthetic HTML regression literals are intentional.
"""Fail-closed and clean-content controls for HTML script-close scanning."""
from __future__ import annotations

import traceback
from pathlib import Path

import pytest

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.io.git_files import GitFileEnumerationError
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parents[2] / "sentinel" / "rules" / "plugins"
    / "script_close_in_template.py"
)


def _scan(root: Path):
    rule = load_plugin_rule(PLUGIN_PATH)
    return rule.check(RepoContext(repo_root=root, mode=ScanMode.REPO))


def test_unreadable_html_candidate_is_fatal_not_silent(
    tmp_path: Path, monkeypatch,
):
    candidate = tmp_path / "page.html"
    candidate.write_text(
        "<script>const html = `<div></script>`;</script>\n",
        encoding="utf-8",
    )
    original_read = Path.read_text

    def deny_candidate(self, *args, **kwargs):
        if self == candidate:
            raise PermissionError("PRIVATE_SYNTHETIC_PATH_MUST_NOT_LEAK")
        return original_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", deny_candidate)
    with pytest.raises(GitFileEnumerationError) as exc:
        _scan(tmp_path)
    diagnostic = "".join(traceback.format_exception(exc.value))
    assert "PRIVATE_SYNTHETIC_PATH_MUST_NOT_LEAK" not in diagnostic


def test_readable_bad_html_blocks(tmp_path: Path):
    (tmp_path / "page.html").write_text(
        "<script>const html = `<div></script>`;</script>\n",
        encoding="utf-8",
    )
    verdicts = _scan(tmp_path)
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "P1-script-close-in-template"
    assert verdicts[0].severity == Severity.BLOCK


def test_valid_and_excluded_unreadable_html_remain_clean(
    tmp_path: Path, monkeypatch,
):
    (tmp_path / "good.html").write_text(
        '<script>const html = `<div>${"<"}/script>`;</script>\n',
        encoding="utf-8",
    )
    excluded = tmp_path / "node_modules" / "ignored.html"
    excluded.parent.mkdir()
    excluded.write_text(
        "<script>const html = `<div></script>`;</script>\n",
        encoding="utf-8",
    )
    original_read = Path.read_text

    def deny_excluded(self, *args, **kwargs):
        if self == excluded:
            raise PermissionError("excluded synthetic fixture")
        return original_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", deny_excluded)
    assert _scan(tmp_path) == []
