"""Tests for P2-html-a11y-basics.

INFO-tier rule catching the four most common WCAG misses:
<html> without lang=, missing <title>, <img> without alt=, form
controls without <label for> or aria-label.
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "html_a11y_basics.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def test_severity_is_info_not_warn(tmp_path: Path):
    assert _rule().severity == Severity.INFO, (
        "Must stay at INFO. a11y is gradient — WARN/BLOCK too noisy."
    )


def test_clean_html_no_verdicts(tmp_path: Path):
    (tmp_path / "index.html").write_text(
        '<html lang="en"><head><title>Demo</title></head>'
        '<body><img src="a.png" alt="chart of X">'
        '<label for="n">N</label><input id="n" type="text"></body></html>',
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_missing_lang_flagged(tmp_path: Path):
    (tmp_path / "index.html").write_text(
        "<html><head><title>T</title></head><body></body></html>",
        encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert any("lang=" in v.detail for v in verdicts)


def test_missing_title_flagged(tmp_path: Path):
    (tmp_path / "index.html").write_text(
        '<html lang="en"><head></head><body></body></html>',
        encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert any("<title>" in v.detail for v in verdicts)


def test_img_without_alt_flagged(tmp_path: Path):
    (tmp_path / "index.html").write_text(
        '<html lang="en"><head><title>T</title></head>'
        '<body><img src="a.png"></body></html>',
        encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert any("<img> without alt=" in v.detail for v in verdicts)


def test_img_with_empty_alt_is_fine(tmp_path: Path):
    # alt="" is legitimate for decorative images — must not flag.
    (tmp_path / "index.html").write_text(
        '<html lang="en"><head><title>T</title></head>'
        '<body><img src="a.png" alt=""></body></html>',
        encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert not any("<img>" in v.detail for v in verdicts)


def test_input_without_label_flagged(tmp_path: Path):
    (tmp_path / "index.html").write_text(
        '<html lang="en"><head><title>T</title></head>'
        '<body><input id="n" type="text"></body></html>',
        encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert any("<input>" in v.detail for v in verdicts)


def test_input_with_label_for_is_fine(tmp_path: Path):
    (tmp_path / "index.html").write_text(
        '<html lang="en"><head><title>T</title></head>'
        '<body><label for="n">Count</label>'
        '<input id="n" type="text"></body></html>',
        encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert not any("<input>" in v.detail for v in verdicts)


def test_input_with_aria_label_is_fine(tmp_path: Path):
    (tmp_path / "index.html").write_text(
        '<html lang="en"><head><title>T</title></head>'
        '<body><input aria-label="Count" type="text"></body></html>',
        encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert not any("<input>" in v.detail for v in verdicts)


def test_submit_button_input_not_required_label(tmp_path: Path):
    # <input type="submit"> / "button" / "hidden" / "reset" don't need labels.
    (tmp_path / "index.html").write_text(
        '<html lang="en"><head><title>T</title></head>'
        '<body><input type="submit" value="Go">'
        '<input type="hidden" name="x" value="1"></body></html>',
        encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert not any("<input>" in v.detail for v in verdicts)


def test_textarea_and_select_also_checked(tmp_path: Path):
    (tmp_path / "index.html").write_text(
        '<html lang="en"><head><title>T</title></head><body>'
        '<textarea id="t"></textarea>'
        '<select id="s"><option>a</option></select>'
        '</body></html>',
        encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    tags = {v.detail.split(">")[0].lstrip("<") for v in verdicts
            if v.detail.startswith("<")}
    assert "textarea" in tags
    assert "select" in tags


def test_non_html_file_ignored(tmp_path: Path):
    (tmp_path / "snippet.txt").write_text(
        "<html><body><img src=x></body></html>", encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_large_file_skipped(tmp_path: Path):
    big = tmp_path / "big.html"
    # > MAX_FILE_BYTES so skipped entirely
    big.write_text("<html><img src=x>" + "x" * 5_200_000, encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_line_numbers_reported_on_match(tmp_path: Path):
    (tmp_path / "index.html").write_text(
        '<html lang="en">\n<head><title>T</title></head>\n<body>\n'
        '<img src="a.png">\n'
        '</body></html>',
        encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    img_verdicts = [v for v in verdicts if "<img>" in v.detail]
    assert len(img_verdicts) == 1
    assert img_verdicts[0].line == 4
