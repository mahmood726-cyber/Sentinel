"""Tests for P1-nullish-or-mixed.

Fires on `?? ... ||` or `?? ... &&` JavaScript expressions without
explicit grouping parentheses. Past incident: lessons.md
"?? ... || mixing: SyntaxError".
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "nullish_or_mixed.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def test_severity_is_block(tmp_path):
    """Block — it's a JS parse-time SyntaxError, not a stylistic issue."""
    assert _rule().severity == Severity.BLOCK


def test_fires_on_nullish_then_or(tmp_path):
    (tmp_path / "bad.js").write_text("const x = a ?? b || c;\n", encoding="utf-8")
    assert len(_rule().check(_ctx(tmp_path))) == 1


def test_fires_on_or_then_nullish(tmp_path):
    (tmp_path / "bad.js").write_text("const y = a || b ?? c;\n", encoding="utf-8")
    assert len(_rule().check(_ctx(tmp_path))) == 1


def test_fires_on_nullish_and(tmp_path):
    """The lesson also covers ?? + && — same SyntaxError class."""
    (tmp_path / "bad.js").write_text("const z = foo.bar ?? quux && baz;\n", encoding="utf-8")
    assert len(_rule().check(_ctx(tmp_path))) == 1


def test_quiet_when_grouped_with_parens(tmp_path):
    (tmp_path / "good.js").write_text("const x = a ?? (b || c);\n", encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_when_pattern_in_string_literal(tmp_path):
    """The bad pattern appearing inside a string is not a real expression."""
    (tmp_path / "good.js").write_text('const s = "a ?? b || c";\n', encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_when_pattern_in_line_comment(tmp_path):
    (tmp_path / "good.js").write_text("// a ?? b || c is bad\nconst x = 1;\n", encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_fires_in_inline_script_block(tmp_path):
    (tmp_path / "page.html").write_text(
        "<html><body><script>\n"
        "  const x = a ?? b || c;\n"
        "</script></body></html>\n",
        encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert verdicts[0].file == "page.html"
