"""Tests for P1-fabrication-temporal-impossibility.

This rule had NO test: mutation testing on 2026-08-30 replaced its `check()`
with `return []` and the suite stayed green, so its destruction was invisible.

What it guards (E156 Assurance Standard, fabrication-detection family):
  - trial years in the future;
  - trial years before the configured CONSORT-era floor;
  - follow-up durations whose implied completion extends beyond the plausible
    publication window.

Assertions state the REQUIREMENT (a chronologically impossible trial must warn),
not the current message text, so rewording the detail does not break them. The
positive has a matching negative so the rule cannot be "fixed" by firing on
everything.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "fabrication_temporal_impossibility.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _page(entry_fields: str) -> str:
    """A minimal rapidmeta-style review page carrying one realData trial."""
    return (
        "<html><script>\n"
        "const realData = {\n"
        "  'NCT01035255': { " + entry_fields + " }\n"
        "};\n"
        "</script></html>"
    )


def _run(body: str, name: str = "HFREF_NMA_REVIEW.html"):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / name).write_text(body, encoding="utf-8")
        return _rule().check(RepoContext(repo_root=p, mode=ScanMode.REPO))


def _temporal_warns(v):
    return [
        x for x in v
        if x.rule_id == "P1-fabrication-temporal-impossibility"
        and x.severity == Severity.WARN
    ]


# --------------------------------------------------------------- severity


def test_severity_is_warn():
    """Temporal impossibilities are suspicious and must surface as warnings."""
    assert _rule().severity == Severity.WARN


# ----------------------------------------------------- impossible chronology


def test_warns_when_trial_year_is_in_future():
    """A trial year that has not happened yet is chronologically impossible."""
    v = _run(_page("year: 9999, follow_up_months: 12"))
    assert len(_temporal_warns(v)) >= 1, "future trial year must WARN; got %r" % (v,)


def test_does_not_warn_on_plausible_trial_year_and_follow_up():
    """Negative control: a recent completed trial with short follow-up is plausible."""
    v = _run(_page("year: 2020, follow_up_months: 12"))
    assert v == [], "plausible chronology must produce nothing; got %r" % (v,)


# --------------------------------------------------------------- scoping


def test_ignores_unrelated_html_filename():
    """Scope is *_REVIEW.html; other pages are out of scope."""
    v = _run(_page("year: 9999, follow_up_months: 12"), name="index.html")
    assert v == [], "out-of-scope filename must produce nothing; got %r" % (v,)
