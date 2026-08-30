"""Tests for P0-denominator-logic.

This rule had NO test: mutation testing on 2026-08-30 replaced its `check()`
with `return []` and the suite stayed green, so its destruction was invisible.
It is one of the two survivors whose failure puts a WRONG NUMBER in front of a
clinician, which is why it is tested first.

What it guards (E156 Assurance Standard, "Data extraction errors"):
  - event counts exceeding their own denominator (tE > tN, cE > cN);
  - a published hazard ratio lying outside its own confidence interval;
  - single-digit cohorts on a phase-3 trial (usually a unit error);
  - zero-width confidence intervals.

Assertions state the REQUIREMENT (an arithmetically impossible count must
block), not the current message text, so rewording the detail does not break
them. Every positive has a matching negative so the rule cannot be "fixed" by
firing on everything.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "denominator_logic.py"
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


def _blocks(v):
    return [x for x in v if x.severity == Severity.BLOCK]


def _warns(v):
    return [x for x in v if x.severity == Severity.WARN]


# --------------------------------------------------------------- severity


def test_severity_is_block():
    """An impossible count is not a style issue -- it must stop a push."""
    assert _rule().severity == Severity.BLOCK


# ------------------------------------------- events exceeding denominators


def test_blocks_treatment_events_exceeding_total():
    """tE > tN is arithmetically impossible."""
    v = _run(_page("tE: 4200, tN: 4187, cE: 835, cN: 4212"))
    assert len(_blocks(v)) >= 1, "tE > tN must BLOCK; got %r" % (v,)


def test_blocks_control_events_exceeding_total():
    """cE > cN is arithmetically impossible."""
    v = _run(_page("tE: 711, tN: 4187, cE: 5000, cN: 4212"))
    assert len(_blocks(v)) >= 1, "cE > cN must BLOCK; got %r" % (v,)


def test_does_not_block_valid_counts():
    """Negative control: the real PARADIGM-HF numbers must stay silent."""
    v = _run(_page("tE: 711, tN: 4187, cE: 835, cN: 4212"))
    assert _blocks(v) == [], "valid 2x2 must not BLOCK; got %r" % (_blocks(v),)


def test_does_not_block_events_equal_to_total():
    """Boundary: every participant having the event is possible, not impossible."""
    v = _run(_page("tE: 100, tN: 100, cE: 50, cN: 100"))
    assert _blocks(v) == [], "tE == tN must not BLOCK; got %r" % (_blocks(v),)


# ------------------------------------------ effect outside its own interval


def test_blocks_hr_outside_its_confidence_interval():
    """A point estimate must lie within its own CI."""
    v = _run(_page("tE: 711, tN: 4187, cE: 835, cN: 4212, "
                   "publishedHR: 0.80, hrLCI: 0.90, hrUCI: 0.99"))
    assert len(_blocks(v)) >= 1, "HR outside CI must BLOCK; got %r" % (v,)


def test_does_not_block_hr_inside_its_confidence_interval():
    """Negative control: the real PARADIGM-HF HR and CI must stay silent."""
    v = _run(_page("tE: 711, tN: 4187, cE: 835, cN: 4212, "
                   "publishedHR: 0.80, hrLCI: 0.73, hrUCI: 0.87"))
    assert _blocks(v) == [], "HR inside CI must not BLOCK; got %r" % (_blocks(v),)


def test_does_not_block_when_bounds_are_null():
    """A missing CI is a gap, not an arithmetic impossibility."""
    v = _run(_page("tE: 711, tN: 4187, cE: 835, cN: 4212, "
                   "publishedHR: 0.80, hrLCI: null, hrUCI: null"))
    assert _blocks(v) == [], "null bounds must not BLOCK; got %r" % (_blocks(v),)


# ------------------------------------------------------------- warn cases


def test_warns_on_zero_width_confidence_interval():
    """hrLCI == hrUCI is almost always a data-entry error."""
    v = _run(_page("tE: 10, tN: 4187, cE: 12, cN: 4212, "
                   "publishedHR: 0.85, hrLCI: 0.85, hrUCI: 0.85"))
    assert len(_warns(v)) >= 1, "zero-width CI must WARN; got %r" % (v,)


# --------------------------------------------------------------- scoping


def test_ignores_file_without_realdata_block():
    """No realData block means nothing to check."""
    v = _run("<html><script>var x = {tE: 99, tN: 1};</script></html>")
    assert v == [], "page without realData must produce nothing; got %r" % (v,)


def test_ignores_unrelated_html_filename():
    """Scope is *_REVIEW.html and students.html; other pages are out of scope."""
    v = _run(_page("tE: 4200, tN: 4187, cE: 835, cN: 4212"), name="index.html")
    assert v == [], "out-of-scope filename must produce nothing; got %r" % (v,)
