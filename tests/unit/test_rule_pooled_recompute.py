# sentinel:skip-file — fixtures contain example mismatched pooled estimates.
"""Tests for P1-pooled-recompute.

Math is checked on an analytically exact symmetric case (two identical trials
whose log-CI is symmetric about the point estimate -> pooled == that estimate,
tau^2 == 0). Behavior is checked through the loaded rule on HTML fixtures.
"""
from __future__ import annotations

import math
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule
from sentinel.rules.plugins.pooled_recompute import pool_hr_ci


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "pooled_recompute.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(p: Path) -> RepoContext:
    return RepoContext(repo_root=p, mode=ScanMode.REPO)


def _review(tmp_path: Path, body_claim: str, trials_js: str) -> Path:
    html = (
        "<html><body>\n"
        f"<p>{body_claim}</p>\n"
        "<script>\nrealData = {\n" + trials_js + "\n};\n</script></body></html>\n"
    )
    p = tmp_path / "x_REVIEW.html"
    p.write_text(html, encoding="utf-8")
    return p


# Two identical trials with log-symmetric CIs about 0.50 -> exact pooled 0.50.
_TRIALS_050 = (
    " 'NCT01111111': { publishedHR:0.50, hrLCI:0.40, hrUCI:0.625, tE:10, tN:100, cE:18, cN:100 },\n"
    " 'NCT02222222': { publishedHR:0.50, hrLCI:0.40, hrUCI:0.625, tE:11, tN:100, cE:19, cN:100 }"
)

# Two trials that pool to ~1.00 (re-pool within 5% of the null) — used to test
# that a near-null re-pool falls through to the magnitude branch.
_TRIALS_NULL = (
    " 'NCT03333333': { publishedHR:1.00, hrLCI:0.90, hrUCI:1.11 },\n"
    " 'NCT04444444': { publishedHR:1.00, hrLCI:0.90, hrUCI:1.11 }"
)


# ---- math ------------------------------------------------------------------

def test_pool_exact_symmetric_case():
    trials = [("NCT01111111", 0.50, 0.40, 0.625), ("NCT02222222", 0.50, 0.40, 0.625)]
    fe, re, k = pool_hr_ci(trials)
    assert k == 2
    assert math.isclose(fe, 0.50, abs_tol=1e-9)
    assert math.isclose(re, 0.50, abs_tol=1e-9)  # identical trials -> tau^2 = 0


def test_pool_needs_two_valid_trials():
    assert pool_hr_ci([("NCT01111111", 0.50, 0.40, 0.625)]) is None
    # impossible CI (hr outside [lci,uci]) is dropped -> only 1 usable -> None
    assert pool_hr_ci([
        ("NCT01111111", 0.50, 0.40, 0.625),
        ("NCT02222222", 0.40, 0.65, 0.95),
    ]) is None


# ---- rule behavior ---------------------------------------------------------

def test_consistent_pooled_claim_clean(tmp_path):
    _review(tmp_path, "Pooled HR 0.50 (95% CI 0.42-0.59).", _TRIALS_050)
    assert _rule().check(_ctx(tmp_path)) == []


def test_direction_contradiction_warns(tmp_path):
    # data pool to 0.50 (protective) but the body claims 1.50 (harm)
    _review(tmp_path, "Pooled HR 1.50 (95% CI 1.20-1.80).", _TRIALS_050)
    vs = _rule().check(_ctx(tmp_path))
    assert len(vs) == 1
    assert "OPPOSITE" in vs[0].detail


def test_magnitude_mismatch_warns(tmp_path):
    # same direction (<1) but 0.80 is well outside the [0.425, 0.575] window
    _review(tmp_path, "Pooled HR 0.80 (95% CI 0.70-0.92).", _TRIALS_050)
    vs = _rule().check(_ctx(tmp_path))
    assert len(vs) == 1
    assert vs[0].severity == Severity.WARN
    assert "outside a re-pool" in vs[0].detail


def test_skip_marker_ignored(tmp_path):
    p = _review(tmp_path, "Pooled HR 1.50 (95% CI 1.20-1.80).", _TRIALS_050)
    p.write_text("sentinel:skip-file\n" + p.read_text(encoding="utf-8"), encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_block_opt_in_promotes_direction_to_block(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_POOLED_RECOMPUTE_BLOCK", "1")
    _review(tmp_path, "Pooled HR 1.50 (95% CI 1.20-1.80).", _TRIALS_050)
    # load AFTER setting env so the module-level opt-in flag picks it up
    rule = load_plugin_rule(PLUGIN_PATH)
    vs = rule.check(_ctx(tmp_path))
    assert len(vs) == 1
    assert vs[0].severity == Severity.BLOCK


def test_prose_wording_does_not_evade(tmp_path):
    # "the hazard ratio was 1.50" is not matched by the strict measure+number
    # regex, but the prose matcher (CI required) catches it.
    _review(tmp_path, "Overall the hazard ratio was 1.50 (95% CI 1.20-1.80).", _TRIALS_050)
    vs = _rule().check(_ctx(tmp_path))
    assert len(vs) == 1
    assert "OPPOSITE" in vs[0].detail


def test_cushion_allows_small_drift(tmp_path):
    # re-pool is 0.50; 0.56 is outside the raw [0.50,0.50] point but inside the
    # +/-15% cushion [0.425,0.575] -> must NOT fire (proves WIDEN is load-bearing).
    _review(tmp_path, "Pooled HR 0.56 (95% CI 0.48-0.65).", _TRIALS_050)
    assert _rule().check(_ctx(tmp_path)) == []


def test_near_null_repool_uses_magnitude_not_direction(tmp_path):
    # re-pool ~1.00: the direction predicate must NOT fire (re not clear of
    # null); the claim 1.30 is caught by the magnitude branch instead.
    _review(tmp_path, "Pooled HR 1.30 (95% CI 1.10-1.55).", _TRIALS_NULL)
    vs = _rule().check(_ctx(tmp_path))
    assert len(vs) == 1
    assert "outside a re-pool" in vs[0].detail
