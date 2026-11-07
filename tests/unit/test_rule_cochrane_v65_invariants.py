"""Tests for P1-cochrane-v65-invariants.

This rule had NO test naming it: mutation testing on 2026-08-30 replaced its
`check()` with `return []` and the suite stayed green, so the rule could vanish
silently.

What it guards (Cochrane Handbook v6.5 / RevMan-2025 dashboard invariants):
  - REML present and primary over DL;
  - Q-profile tau2 CI helper defined and called;
  - qchisq closed-form coverage for df=1;
  - HKSJ floor at max(1, q*);
  - prediction-interval df set to k-1;
  - Mantel-Haenszel sensitivity pooling;
  - ROB-ME assessment defined and invoked.

Assertions state the REQUIREMENT (a RapidMeta dashboard missing a required
statistical invariant must WARN), not the current detail sentence. The clean
fixture carries every required invariant so the rule cannot be "fixed" by
firing on every scoped dashboard.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "cochrane_v65_invariants.py"
)
RULE_ID = "P1-cochrane-v65-invariants"


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _dashboard(hksj_line: str = "const hksjAdj = Math.max(1, qStar);") -> str:
    """A minimal RapidMeta-style review page with all v6.5 invariants."""
    return f"""<html><script>
const realData = {{
  'NCT01035255': {{ tE: 711, tN: 4187, cE: 835, cN: 4212 }}
}};

class AnalysisEngine {{
  updateStatCards(plotData) {{
    const k = plotData.length;
    const df = k - 1;
    const tau2_reml = 0.01;
    const tau2_dl = 0.02;
    const tau2 = (k >= 2) ? tau2_reml : tau2_dl;
    const qStar = 0.72;
    {hksj_line}
    // PI df = k-1 per Cochrane Handbook v6.5

    const qchisq = (p, df) => {{
      if (df === 1) return 0.0;
      return p * df;
    }};

    const qProfileTau2CI = (yi, vi, df, alpha) => {{
      return [0, qchisq(1 - alpha, df)];
    }};
    const tau2CI = qProfileTau2CI([], [], df, 0.05);

    const methods = [];
    methods.push({{ name: 'Mantel-Haenszel', result: this.mhPool(plotData, 0.95) }});
    const robme = this._assessROBME({{ tau2, tau2CI, hksjAdj }});
    return {{ methods, robme }};
  }}

  mhPool(plotData, confLevel) {{
    return {{ plotData, confLevel }};
  }}

  _assessROBME(c) {{
    return c;
  }}
}}
</script></html>"""


def _run(body: str, name: str = "HFREF_NMA_REVIEW.html"):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / name).write_text(body, encoding="utf-8")
        return _rule().check(RepoContext(repo_root=p, mode=ScanMode.REPO))


def _rule_warns(v):
    return [x for x in v if x.rule_id == RULE_ID and x.severity == Severity.WARN]


# --------------------------------------------------------------- severity


def test_severity_is_warn():
    """Cochrane v6.5 drift is a quality warning, not a push block."""
    assert _rule().severity == Severity.WARN


# ---------------------------------------------------------- required checks


def test_warns_when_hksj_floor_is_missing():
    """A RapidMeta review dashboard must retain the HKSJ max(1, q*) floor."""
    v = _run(_dashboard(hksj_line="const hksjAdj = qStar;"))
    warns = _rule_warns(v)
    assert len(warns) >= 1, "missing HKSJ floor must WARN; got %r" % (v,)


def test_does_not_warn_when_all_v65_invariants_are_present():
    """Negative control: a scoped dashboard with every invariant stays silent."""
    v = _run(_dashboard())
    assert v == [], "complete Cochrane v6.5 invariant set must be silent; got %r" % (v,)


# --------------------------------------------------------------- scoping


def test_ignores_dta_review_dashboards():
    """DTA review dashboards use a different engine and are out of scope."""
    v = _run(_dashboard(hksj_line="const hksjAdj = qStar;"), name="HFREF_DTA_REVIEW.html")
    assert v == [], "DTA dashboards must be ignored; got %r" % (v,)


def test_ignores_review_page_without_realdata_marker():
    """The rule only applies to RapidMeta-shaped pages with realData."""
    body = _dashboard().replace("const realData =", "const trialData =")
    v = _run(body)
    assert v == [], "review page without realData must be ignored; got %r" % (v,)
