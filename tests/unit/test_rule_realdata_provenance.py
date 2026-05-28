# sentinel:skip-file — fixtures contain example realData blocks.
"""Tests for P1-realdata-provenance (fires only on inconsistent provenance)."""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "realdata_provenance.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(p: Path) -> RepoContext:
    return RepoContext(repo_root=p, mode=ScanMode.REPO)


def _dash(tmp_path: Path, realdata: str) -> None:
    (tmp_path / "x_REVIEW.html").write_text(
        "<html><body><script>\n" + realdata + "\n</script></body></html>\n",
        encoding="utf-8",
    )


_ALL = (
    "realData = {"
    " 'NCT01111111': { publishedHR:0.80, hrLCI:0.70, hrUCI:0.90, source:'Smith 2020 Table 2' },"
    " 'NCT02222222': { publishedHR:0.85, hrLCI:0.75, hrUCI:0.95, source:'Jones 2021 Table 1' } };"
)
_NONE = (
    "realData = {"
    " 'NCT01111111': { publishedHR:0.80, hrLCI:0.70, hrUCI:0.90 },"
    " 'NCT02222222': { publishedHR:0.85, hrLCI:0.75, hrUCI:0.95 } };"
)
_MIXED = (
    "realData = {"
    " 'NCT01111111': { publishedHR:0.80, hrLCI:0.70, hrUCI:0.90, source:'Smith 2020 Table 2' },"
    " 'NCT02222222': { publishedHR:0.85, hrLCI:0.75, hrUCI:0.95 } };"
)


def test_all_rows_have_provenance_clean(tmp_path):
    _dash(tmp_path, _ALL)
    assert _rule().check(_ctx(tmp_path)) == []


def test_no_rows_have_provenance_clean(tmp_path):
    # convention not adopted -> don't flood; stay silent
    _dash(tmp_path, _NONE)
    assert _rule().check(_ctx(tmp_path)) == []


def test_mixed_provenance_warns_on_missing(tmp_path):
    _dash(tmp_path, _MIXED)
    vs = _rule().check(_ctx(tmp_path))
    assert len(vs) == 1
    assert "NCT02222222" in vs[0].detail


def test_skip_marker_ignored(tmp_path):
    (tmp_path / "x_REVIEW.html").write_text(
        "sentinel:skip-file\n<script>\n" + _MIXED + "\n</script>\n", encoding="utf-8"
    )
    assert _rule().check(_ctx(tmp_path)) == []
