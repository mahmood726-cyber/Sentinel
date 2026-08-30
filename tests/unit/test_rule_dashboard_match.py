"""Tests for P1-dashboard-match.

This rule had NO test naming it: mutation testing on 2026-08-30 replaced its
`check()` with `return []` and the suite stayed green, so its destruction was
invisible.

What it guards (E156 Assurance Standard, "dashboard_match"):
  - a rendered review page whose body-level pooled HR/OR/RR/IRR claim is
    implausibly outside the per-trial HR values in that same page's realData
    block.

Assertions state the REQUIREMENT (the body claim must be compatible with the
same file's per-trial HR values), not the current message text, so rewording
the detail does not break them. The positive has a matching negative so the
rule cannot be "fixed" by firing on everything.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "dashboard_match.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _page(body_claim: str) -> str:
    """A minimal rapidmeta-style review page with two realData trials."""
    return (
        "<html><body>\n"
        f"<p>{body_claim}</p>\n"
        "</body><script>\n"
        "const realData = {\n"
        "  'NCT00000001': { publishedHR: 0.70, hrLCI: 0.55, hrUCI: 0.90 },\n"
        "  'NCT00000002': { publishedHR: 0.95, hrLCI: 0.80, hrUCI: 1.10 }\n"
        "};\n"
        "</script></html>"
    )


def _run(body: str, name: str = "HFREF_NMA_REVIEW.html"):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / name).write_text(body, encoding="utf-8")
        return _rule().check(RepoContext(repo_root=p, mode=ScanMode.REPO))


def _warns(v):
    return [x for x in v if x.severity == Severity.WARN]


# --------------------------------------------------------------- severity


def test_severity_is_warn():
    """A stale pooled dashboard claim should warn, not block."""
    assert _rule().severity == Severity.WARN


# --------------------------------------- pooled claim vs per-trial HR range


def test_warns_when_body_pooled_hr_is_outside_realdata_trial_range():
    """A pooled claim far outside all per-trial HRs is internally inconsistent."""
    v = _run(_page("Pooled HR 1.60 (95% CI 1.40-1.80)"))
    warns = _warns(v)

    assert len(warns) == 1, (
        "pooled HR beyond the realData per-trial HR range plus tolerance "
        "must WARN; got %r" % (v,)
    )
    assert warns[0].rule_id == "P1-dashboard-match"
    assert warns[0].severity == Severity.WARN


def test_does_not_warn_when_body_pooled_hr_is_inside_realdata_trial_range():
    """Negative control: a compatible pooled claim must stay silent."""
    v = _run(_page("Pooled HR 0.82 (95% CI 0.70-0.96)"))
    assert v == [], "compatible pooled HR must produce nothing; got %r" % (v,)


# --------------------------------------------------------------- scoping


def test_ignores_unrelated_html_filename():
    """Scope is root-level *_REVIEW.html only."""
    v = _run(_page("Pooled HR 1.60 (95% CI 1.40-1.80)"), name="index.html")
    assert v == [], "out-of-scope filename must produce nothing; got %r" % (v,)
