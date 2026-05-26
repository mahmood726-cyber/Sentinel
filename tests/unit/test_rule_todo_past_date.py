# sentinel:skip-file — test fixtures literally contain past-date TODO markers.
"""Tests for P2-todo-past-date.

INFO-tier rule that re-surfaces TODO/FIXME/HACK markers whose
explicit YYYY-MM-DD deadline has passed.
"""
from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "todo_past_date.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def test_severity_is_info(tmp_path):
    """INFO, not WARN — these are scheduled tasks, not bugs."""
    assert _rule().severity == Severity.INFO


def test_fires_on_overdue_todo(tmp_path):
    """TODO with a past-date — the canonical fire."""
    (tmp_path / "bad.py").write_text(
        "# TODO(2024-01-01): clean up\nx = 1\n", encoding="utf-8"
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert "overdue" in verdicts[0].detail
    assert "2024-01-01" in verdicts[0].detail


def test_fires_on_fixme_paren_form(tmp_path):
    """FIXME(YYYY-MM-DD) — different keyword, same date format."""
    (tmp_path / "bad.py").write_text(
        "# FIXME(2025-12-01) drop alias\n", encoding="utf-8"
    )
    assert len(_rule().check(_ctx(tmp_path))) == 1


def test_fires_on_hack_space_form(tmp_path):
    """HACK <date> — bracket-less form (date follows keyword + space)."""
    (tmp_path / "bad.js").write_text(
        "// HACK 2025-06-15 — workaround\n", encoding="utf-8"
    )
    assert len(_rule().check(_ctx(tmp_path))) == 1


def test_quiet_on_future_date(tmp_path):
    """Date in the future — not overdue, don't fire."""
    (tmp_path / "good.py").write_text(
        "# TODO(2099-01-01): scheduled\n", encoding="utf-8"
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_today(tmp_path):
    """Date equal to today's date — not yet overdue."""
    today = date.today().isoformat()
    (tmp_path / "good.py").write_text(
        f"# TODO({today}): today\n", encoding="utf-8"
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_dateless_todo(tmp_path):
    """Plain TODO with no date — not in scope (no deadline to compare)."""
    (tmp_path / "good.py").write_text(
        "# TODO: someday\n# FIXME: also someday\n", encoding="utf-8"
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_invalid_date(tmp_path):
    """Impossible dates (Feb 31) don't crash — just skip."""
    (tmp_path / "good.py").write_text(
        "# TODO(2026-02-31): impossible\n", encoding="utf-8"
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_skip_line_marker_extends_deadline(tmp_path):
    """`# sentinel:skip-line P2-todo-past-date` is the formal way to
    extend a deadline without re-dating the comment."""
    (tmp_path / "good.py").write_text(
        "# sentinel:skip-line P2-todo-past-date\n"
        "# TODO(2024-01-01): extended\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_days_overdue_in_detail(tmp_path):
    """Detail message includes days overdue so the operator sees how
    long the deadline has slipped."""
    overdue_date = (date.today() - timedelta(days=42)).isoformat()
    (tmp_path / "bad.py").write_text(
        f"# TODO({overdue_date}): aged\n", encoding="utf-8"
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert "42 day(s) overdue" in verdicts[0].detail
