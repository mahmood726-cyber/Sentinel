# sentinel:skip-file — synthetic examples deliberately contain invalid JS.
"""Fail-closed and valid-code controls for P1-nullish-or-mixed reads."""
from __future__ import annotations

import traceback
from pathlib import Path

import pytest

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.io.git_files import GitFileEnumerationError
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parents[2] / "sentinel" / "rules" / "plugins"
    / "nullish_or_mixed.py"
)

BAD_JS = "const broken = a ?? b || c;\n"
BAD_HTML = "<script>const broken = a ?? b || c;</script>\n"


def _scan(root: Path):
    rule = load_plugin_rule(PLUGIN_PATH)
    return rule.check(RepoContext(repo_root=root, mode=ScanMode.REPO))


@pytest.mark.parametrize(
    ("filename", "content"),
    [("src/bad.js", BAD_JS), ("page.html", BAD_HTML)],
)
def test_inaccessible_candidate_aborts_instead_of_missing_block(
    tmp_path: Path, monkeypatch, filename: str, content: str,
):
    candidate = tmp_path / filename
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_text(content, encoding="utf-8")
    original_read = Path.read_text

    def deny_candidate(self, *args, **kwargs):
        if self == candidate:
            raise PermissionError("PRIVATE_SYNTHETIC_PATH_MUST_NOT_LEAK")
        return original_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", deny_candidate)
    with pytest.raises(GitFileEnumerationError) as exc:
        _scan(tmp_path)
    rendered = "".join(traceback.format_exception(exc.value))
    assert "PRIVATE_SYNTHETIC_PATH_MUST_NOT_LEAK" not in rendered


@pytest.mark.parametrize(
    ("filename", "content"),
    [("src/bad.js", BAD_JS), ("page.html", BAD_HTML)],
)
def test_readable_invalid_expression_still_blocks(
    tmp_path: Path, filename: str, content: str,
):
    candidate = tmp_path / filename
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_text(content, encoding="utf-8")
    verdicts = _scan(tmp_path)
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "P1-nullish-or-mixed"
    assert verdicts[0].severity == Severity.BLOCK


def test_valid_js_html_and_excluded_bad_candidate_do_not_block(
    tmp_path: Path, monkeypatch,
):
    (tmp_path / "valid.js").write_text(
        "const x = a ?? (b || c);\n", encoding="utf-8"
    )
    (tmp_path / "valid.html").write_text(
        "<script>const x = (a ?? b) || c;</script>\n", encoding="utf-8"
    )
    ignored = tmp_path / "node_modules" / "ignored.js"
    ignored.parent.mkdir()
    ignored.write_text(BAD_JS, encoding="utf-8")
    original_read = Path.read_text

    def deny_excluded(self, *args, **kwargs):
        if self == ignored:
            raise PermissionError("excluded synthetic fixture")
        return original_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", deny_excluded)
    assert _scan(tmp_path) == []
