"""Tests for P0-e156-placeholder-leak.

This rule had NO test at all: mutation testing on 2026-08-30 replaced its
`check()` with `return []` and the whole suite stayed green, so the rule was
decorative -- its destruction was invisible.

What it guards (lessons.md#placeholder-leak:2026-05-24):
  - 1110 dashboards in rapidmeta-finerenone shipped `publishedHR: None` inside
    inline JS, throwing `ReferenceError: None is not defined` and rendering
    every *_AUTO_FULL_REVIEW.html as a 626-byte stub;
  - 1208 rewrite-workbook.txt entries leaked a literal `n` participants token;
  - workbook link lines resolved to the literal string `None`.

Each test below asserts the REQUIREMENT (a Python-None literal reaching JS is a
blocker), not the current wording, so a rewrite of the message does not fail
them. Negative cases assert the valid form stays silent, so the rule cannot be
"fixed" by making it fire on everything.
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "e156_placeholder_leak.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def _students(tmp_path: Path, body: str) -> None:
    (tmp_path / "students.html").write_text(body, encoding="utf-8")


def _workbook(tmp_path: Path, body: str) -> None:
    (tmp_path / "rewrite-workbook.txt").write_text(body, encoding="utf-8")


# --------------------------------------------------------------- severity


def test_severity_is_block():
    """A Python None reaching JS is a runtime ReferenceError that blanks the
    whole page -- it must stop a push, not warn."""
    assert _rule().severity == Severity.BLOCK


# ------------------------------------------------- the 1110-dashboard bug


def test_blocks_python_none_in_inline_js():
    """The exact 2026-05-24 shape: `publishedHR: None` inside a <script>."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        _students(p, "<html><script>\nvar d = {publishedHR: None};\n</script></html>")
        v = _rule().check(_ctx(p))
        blocks = [x for x in v if x.severity == Severity.BLOCK]
        assert len(blocks) >= 1, "None-in-JS must BLOCK; got %r" % (v,)
        assert blocks[0].file == "students.html"


def test_does_not_block_valid_js_null():
    """Negative control: `null` is correct JS and must stay silent, otherwise
    the rule fires on every fixed file and gets bypassed."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        _students(p, "<html><script>\nvar d = {publishedHR: null};\n</script></html>")
        blocks = [x for x in _rule().check(_ctx(p)) if x.severity == Severity.BLOCK]
        assert blocks == [], "valid JS null must not BLOCK; got %r" % (blocks,)


def test_does_not_block_css_none_lowercase():
    """`display: none` is CSS, not a Python None. Case matters."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        _students(p, "<html><script>\nel.style.display = 'none';\n</script></html>")
        blocks = [x for x in _rule().check(_ctx(p)) if x.severity == Severity.BLOCK]
        assert blocks == [], "lowercase css none must not BLOCK; got %r" % (blocks,)


# ------------------------------------------------------ workbook link leak


def test_blocks_workbook_none_link():
    """`Dashboard: None` is a Python None that reached a link line."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        _workbook(p, "Entry 1\n    Dashboard: None\n")
        blocks = [x for x in _rule().check(_ctx(p)) if x.severity == Severity.BLOCK]
        assert len(blocks) >= 1, "workbook None link must BLOCK; got nothing"


def test_blocks_workbook_url_ending_in_none():
    """A URL whose last path segment is the literal `None`."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        _workbook(p, "Entry 1\n    Code: https://github.com/x/None\n")
        blocks = [x for x in _rule().check(_ctx(p)) if x.severity == Severity.BLOCK]
        assert len(blocks) >= 1, "URL ending /None must BLOCK; got nothing"


def test_does_not_block_real_workbook_url():
    """Negative control: a real URL must stay silent."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        _workbook(p, "Entry 1\n    Code: https://github.com/mahmood726-cyber/e156\n")
        blocks = [x for x in _rule().check(_ctx(p)) if x.severity == Severity.BLOCK]
        assert blocks == [], "real URL must not BLOCK; got %r" % (blocks,)


# ------------------------------------------------- the 1208-entry 'n' leak


def test_warns_on_n_participants_placeholder():
    """The literal token `n` where a participant count belongs."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        _workbook(p, "Entry 1\naggregates 4 trials with n participants in a browser\n")
        warns = [x for x in _rule().check(_ctx(p)) if x.severity == Severity.WARN]
        assert len(warns) >= 1, "'with n participants' must WARN; got nothing"


def test_does_not_warn_on_real_participant_count():
    """Negative control: a real count must stay silent."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        _workbook(p, "Entry 1\naggregates 4 trials with 1504 participants in a browser\n")
        warns = [x for x in _rule().check(_ctx(p)) if x.severity == Severity.WARN]
        assert warns == [], "real count must not WARN; got %r" % (warns,)


# --------------------------------------------------------------- scoping


def test_silent_when_neither_target_file_exists():
    """The rule is scoped to students.html + rewrite-workbook.txt; an
    unrelated repo must produce nothing."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / "other.html").write_text(
            "<script>var d = {x: None};</script>", encoding="utf-8")
        assert _rule().check(_ctx(p)) == []
