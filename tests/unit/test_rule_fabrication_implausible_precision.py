"""Tests for P1-fabrication-implausible-precision.

This rule had NO test: mutation testing on 2026-08-30 replaced its `check()`
with `return []` and the suite stayed green. It is the second of the two
survivors whose failure puts a WRONG NUMBER in front of a clinician -- here by
letting a fabricated (copy-pasted) confidence interval through.

What it guards: a 95% CI that is impossibly narrow for the cohort behind it.
The bounds were not computed from these data; they were inherited from a
different trial.

  WARN when width < 0.01 and (tN + cN) < 5000
  WARN when width < 0.05 and (tN + cN) < 500
  skip zero-width CIs (denominator_logic blocks those; do not double-fire)
  skip when any of hrLCI/hrUCI/tN/cN is null

Positives assert the requirement; each has a negative twin on the other side
of the documented threshold, so the rule cannot pass by firing on everything.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "fabrication_implausible_precision.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _page(fields: str) -> str:
    return (
        "<html><script>\n"
        "const realData = {\n"
        "  'NCT01035255': { " + fields + " }\n"
        "};\n"
        "</script></html>"
    )


def _run(fields: str, name: str = "HFREF_NMA_REVIEW.html"):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / name).write_text(_page(fields), encoding="utf-8")
        return _rule().check(RepoContext(repo_root=p, mode=ScanMode.REPO))


def test_severity_is_warn():
    """Suspicious, not arithmetically impossible -- so WARN, not BLOCK."""
    assert _rule().severity == Severity.WARN


def test_warns_on_hairline_ci_at_small_cohort():
    """width 0.002 at n=400: a CI that tight cannot come from this cohort."""
    v = _run("tE: 20, tN: 200, cE: 25, cN: 200, "
             "publishedHR: 0.850, hrLCI: 0.849, hrUCI: 0.851")
    assert len(v) >= 1, "hairline CI at small n must WARN; got %r" % (v,)


def test_warns_on_narrow_ci_at_very_small_cohort():
    """width 0.02 at n=300 trips the second-tier (<0.05 below n=500) rule."""
    v = _run("tE: 15, tN: 150, cE: 18, cN: 150, "
             "publishedHR: 0.850, hrLCI: 0.840, hrUCI: 0.860")
    assert len(v) >= 1, "narrow CI at n<500 must WARN; got %r" % (v,)


def test_does_not_warn_on_realistic_ci_width():
    """Negative control: the real PARADIGM-HF CI (0.73-0.87, width 0.14) at
    n=8399 is exactly what a genuine trial looks like."""
    v = _run("tE: 711, tN: 4187, cE: 835, cN: 4212, "
             "publishedHR: 0.80, hrLCI: 0.73, hrUCI: 0.87")
    assert v == [], "realistic CI must not WARN; got %r" % (v,)


def test_does_not_warn_on_wide_ci_at_small_cohort():
    """A small trial with an appropriately wide CI is correct, not suspicious."""
    v = _run("tE: 15, tN: 150, cE: 18, cN: 150, "
             "publishedHR: 0.85, hrLCI: 0.40, hrUCI: 1.80")
    assert v == [], "wide CI at small n must not WARN; got %r" % (v,)


def test_does_not_double_fire_on_zero_width_ci():
    """denominator_logic already blocks lci == uci; this rule must stay out of
    the way so one defect does not raise two findings."""
    v = _run("tE: 15, tN: 150, cE: 18, cN: 150, "
             "publishedHR: 0.85, hrLCI: 0.85, hrUCI: 0.85")
    assert v == [], "zero-width CI is denominator_logic's; got %r" % (v,)


def test_does_not_warn_when_bounds_are_null():
    """A missing CI is a gap, not a fabricated one."""
    v = _run("tE: 15, tN: 150, cE: 18, cN: 150, "
             "publishedHR: 0.85, hrLCI: null, hrUCI: null")
    assert v == [], "null bounds must not WARN; got %r" % (v,)


def test_ignores_unrelated_html_filename():
    """Scope is *_REVIEW.html (and students.html)."""
    v = _run("tE: 20, tN: 200, cE: 25, cN: 200, "
             "publishedHR: 0.850, hrLCI: 0.849, hrUCI: 0.851",
             name="index.html")
    assert v == [], "out-of-scope filename must produce nothing; got %r" % (v,)
