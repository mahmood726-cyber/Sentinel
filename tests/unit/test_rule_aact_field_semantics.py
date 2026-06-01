"""Tests for P1-aact-field-semantics (fires only on a misleading field used as a filter)."""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode
from sentinel.registry.plugin_loader import load_plugin_rule

PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "aact_field_semantics.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(p: Path) -> RepoContext:
    return RepoContext(repo_root=p, mode=ScanMode.REPO)


def test_fires_on_us_export_filter(tmp_path):
    (tmp_path / "q.py").write_text(
        "sql = \"SELECT * FROM studies WHERE is_us_export = 't'\"\n", encoding="utf-8")
    vs = _rule().check(_ctx(tmp_path))
    assert len(vs) == 1
    assert "is_us_export" in vs[0].detail and "exported" in vs[0].detail.lower()


def test_fires_on_python_eq_and_sql_eq(tmp_path):
    (tmp_path / "a.py").write_text("if row.is_fda_regulated_drug == 't': pass\n", encoding="utf-8")
    (tmp_path / "b.sql").write_text("WHERE is_fda_regulated_device='t'\n", encoding="utf-8")
    vs = _rule().check(_ctx(tmp_path))
    flags = {v.detail.split("'")[1] for v in vs}
    assert flags == {"is_fda_regulated_drug", "is_fda_regulated_device"}


def test_silent_on_prose_mention(tmp_path):
    # mentioned, not filtered -> no comparison operator after the field name
    (tmp_path / "doc.py").write_text(
        "# is_us_export is a field; we never filter on is_us_export here.\n"
        "x = 'the is_us_export column in the table'\n", encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_skip_marker_ignored(tmp_path):
    (tmp_path / "q.py").write_text(
        "# sentinel:skip-file\nWHERE is_us_export = 't'\n", encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_excludes_vendored_and_minified(tmp_path):
    (tmp_path / "_vendor").mkdir()
    (tmp_path / "_vendor" / "v.py").write_text("WHERE is_us_export = 't'\n", encoding="utf-8")
    (tmp_path / "app.min.js").write_text("is_us_export=='t'\n", encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_dedups_per_field_per_line(tmp_path):
    (tmp_path / "q.py").write_text(
        "x = (is_us_export = 't') or (is_us_export = 't')\n", encoding="utf-8")
    vs = _rule().check(_ctx(tmp_path))
    assert len(vs) == 1  # one field, one line -> deduped


def test_silent_on_python_kwarg_and_assignment(tmp_path):
    # portfolio FP audit: kwargs/assignments are NOT filters (single '=' to
    # unquoted or long value). These must NOT fire.
    (tmp_path / "fixtures.py").write_text(
        "make(why_stopped=None)\n"
        "why_stopped = status_mod.get('whyStoppedDescription', '')\n"
        "make(why_stopped='Safety concerns: increased adverse events observed')\n",
        encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_fires_on_real_comparison_and_short_sql_literal(tmp_path):
    (tmp_path / "use.py").write_text(
        "if record.why_stopped == 'terminated': pass\n"          # comparison -> fire
        "sql = \"WHERE last_known_status = 'Completed'\"\n",      # short quoted literal -> fire
        encoding="utf-8")
    vs = _rule().check(_ctx(tmp_path))
    flags = {v.detail.split("'")[1] for v in vs}
    assert flags == {"why_stopped", "last_known_status"}
