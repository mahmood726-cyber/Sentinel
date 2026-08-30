"""Tests for P1-capsule-stats-invariant.

This rule had NO test: mutation testing on 2026-08-30 replaced its `check()`
with `return []` and the suite stayed green, so its destruction was invisible.
It guards the statistical gotchas encoded in capsule self-audits:
  - DerSimonian-Laird used with k<10 without a documenting note;
  - missing prediction intervals when k>=2;
  - failed AACT statistical self-audit checks.

Assertions state the REQUIREMENT (a defective capsule must warn with this rule
id), not the current message text, so rewording the detail does not break them.
Every positive has a matching negative so the rule cannot be "fixed" by firing
on everything.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "capsule_stats_invariant.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _page(capsule_json: str) -> str:
    """A minimal dashboard capsule carrying one literal CAPSULE JSON object."""
    return (
        "<html><script>\n"
        "const CAPSULE = " + capsule_json + ";\n"
        "</script></html>"
    )


def _run(body: str, name: str = "hfref-capsule.html"):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / name).write_text(body, encoding="utf-8")
        return _rule().check(RepoContext(repo_root=p, mode=ScanMode.REPO))


def _warns(v):
    return [x for x in v if x.severity == Severity.WARN]


# --------------------------------------------------------------- severity


def test_severity_is_warn():
    """Capsule statistical invariants warn unless explicitly escalated."""
    assert _rule().severity == Severity.WARN


# -------------------------------------------------------- capsule checks


def test_warns_on_small_k_dl_without_documenting_note():
    """DerSimonian-Laird at k<10 must be explicitly justified."""
    v = _run(_page(
        '{"pooled":{"k":3,"method":"DL","pi_lower":0.72},'
        '"notes":[],"self_audit":{"aact_stats":{"bounds":"pass"}}}'
    ))
    assert any(
        x.rule_id == "P1-capsule-stats-invariant" and x.severity == Severity.WARN
        for x in v
    ), "small-k DL without dl_note must WARN; got %r" % (v,)


def test_does_not_warn_on_supported_capsule_stats():
    """Negative control: supported estimator, PI, and passing audit stay silent."""
    v = _run(_page(
        '{"pooled":{"k":12,"method":"PM","pi_lower":0.72},'
        '"notes":["pre-specified REML sensitivity"],'
        '"self_audit":{"aact_stats":{"bounds":"pass","jensen":"pass"}}}'
    ))
    assert _warns(v) == [], "valid capsule stats must not WARN; got %r" % (_warns(v),)


# --------------------------------------------------------------- scoping


def test_ignores_unrelated_html_filename():
    """Scope is only *-capsule.html."""
    v = _run(_page(
        '{"pooled":{"k":3,"method":"DL","pi_lower":0.72},'
        '"notes":[],"self_audit":{"aact_stats":{"bounds":"pass"}}}'
    ), name="index.html")
    assert v == [], "out-of-scope filename must produce nothing; got %r" % (v,)
