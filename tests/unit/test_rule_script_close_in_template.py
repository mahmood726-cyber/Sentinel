"""Tests for P1-script-close-in-template.

Fires when a literal `</script>` token appears inside a backtick
template literal that hasn't closed before it. Past incident: lessons.md
"</script> in template literals/comments".
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "script_close_in_template.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def test_severity_is_block(tmp_path):
    """Block, not warn — the bug breaks page rendering at parse time."""
    assert _rule().severity == Severity.BLOCK


def test_fires_on_template_literal_with_literal_close(tmp_path):
    (tmp_path / "bad.html").write_text(
        '<html><body><script>\n'
        '  const html = `<div>x</div></script>`;\n'
        '</script></body></html>\n',
        encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert verdicts[0].file == "bad.html"
    assert "template literal" in verdicts[0].detail.lower() or "string" in verdicts[0].detail.lower()


def test_quiet_on_minified_bundle_with_legit_close(tmp_path):
    """Regression for 2026-05-28 portfolio FPs: a minified library bundle
    (e.g. a Plotly export) contains backticks AND a legitimate `</script>`
    closing the bundle's block. The char-scanner can't track template
    boundaries across a 9000-char minified line, so it used to flag the
    real close as 'inside a template'. Files with any very long line are
    now skipped entirely."""
    minified = "var t=`x`;" + "a=1;" * 2000 + "function f(){return `y`}"  # >3000-char line
    (tmp_path / "plotly_export.html").write_text(
        "<html><body><script>\n"
        f"{minified}\n"
        "</script></body></html>\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_far_apart_backtick_and_close(tmp_path):
    """Defense-in-depth: even on normal-length lines, a `</script>` more
    than MAX_TEMPLATE_SPAN chars from the opening backtick is not flagged
    (the real bug is compact)."""
    filler = "x" * 1500
    (tmp_path / "spread.html").write_text(
        "<html><body><script>\n"
        f"const s = `{filler}`;\n"          # backtick closes well before
        "const ok = 1;\n"
        "</script></body></html>\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_when_split_token_used(tmp_path):
    """The canonical fix: `${'<'}/script>` interpolation splits the token."""
    (tmp_path / "good.html").write_text(
        '<html><body><script>\n'
        '  const html = `<div>x</div>${"<"}/script>`;\n'
        '</script></body></html>\n',
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_when_external_src(tmp_path):
    """<script src="..."> has no inline body to scan."""
    (tmp_path / "good.html").write_text(
        '<html><body><script src="foo.js"></script></body></html>\n',
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_html_comment_skip_marker_honored(tmp_path):
    """The marker uses the HTML-comment form Sentinel added 2026-05-25."""
    (tmp_path / "fixture.html").write_text(
        '<!-- sentinel:skip-file — intentional bug -->\n'
        '<script>const x = `<div></script>`;</script>\n',
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []
