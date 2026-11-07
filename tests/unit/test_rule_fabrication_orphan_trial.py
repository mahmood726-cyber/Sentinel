"""Tests for P1-fabrication-orphan-trial.

This rule had NO test: mutation testing on 2026-08-30 replaced its `check()`
with `return []` and the suite stayed green, so its destruction was invisible.

What it guards (E156 Assurance Standard, fabrication-detection family):
  - an NCT id named in review prose must have a matching realData entry;
  - navigation/registry links alone are not data claims;
  - files without a realData block have no extractable source table to check.

Assertions state the REQUIREMENT (a prose NCT claim must be backed by realData),
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
    / "sentinel" / "rules" / "plugins" / "fabrication_orphan_trial.py"
)

RULE_ID = "P1-fabrication-orphan-trial"


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _page(body_claim: str, realdata_entries: str) -> str:
    """A minimal rapidmeta-style review page with prose and realData."""
    return (
        "<html><body>\n"
        f"{body_claim}\n"
        "</body><script>\n"
        "const realData = {\n"
        f"{realdata_entries}\n"
        "};\n"
        "</script></html>"
    )


def _write_review(root: Path, body: str, name: str = "HFREF_NMA_REVIEW.html") -> None:
    (root / name).write_text(body, encoding="utf-8")


def _run(body: str, name: str = "HFREF_NMA_REVIEW.html"):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        _write_review(p, body, name=name)
        return _rule().check(RepoContext(repo_root=p, mode=ScanMode.REPO))


def _warns(v):
    return [x for x in v if x.rule_id == RULE_ID and x.severity == Severity.WARN]


def _trial(nct: str) -> str:
    return (
        f"  '{nct}': {{ tE: 10, tN: 100, cE: 12, cN: 100, "
        "publishedHR: 0.85, hrLCI: 0.70, hrUCI: 1.03 },"
    )


# --------------------------------------------------------------- severity


def test_severity_is_warn():
    """Orphan trial claims should warn, not block."""
    assert _rule().severity == Severity.WARN


# --------------------------------------------------------- orphan detection


def test_warns_when_body_nct_is_missing_from_realdata():
    """A prose NCT claim must be backed by a matching realData entry."""
    v = _run(_page(
        "<p>We pooled NCT01035255 with NCT99999999 for mortality.</p>",
        _trial("NCT01035255"),
    ))
    assert len(_warns(v)) >= 1, "body NCT absent from realData must WARN; got %r" % (v,)


def test_does_not_warn_when_body_ncts_are_all_in_realdata():
    """Negative control: realData-backed prose claims must stay silent."""
    v = _run(_page(
        "<p>We pooled NCT01035255 with NCT02984410 for mortality.</p>",
        "\n".join([
            _trial("NCT01035255"),
            _trial("NCT02984410"),
        ]),
    ))
    assert _warns(v) == [], "all body NCTs present in realData must not WARN; got %r" % (_warns(v),)


# ---------------------------------------------------------------- scoping


def test_ignores_file_without_realdata_block():
    """No realData block means nothing to cross-check."""
    v = _run("<html><body><p>We pooled NCT99999999.</p></body></html>")
    assert v == [], "page without realData must produce nothing; got %r" % (v,)


def test_ignores_unrelated_html_filename():
    """Scope is top-level *_REVIEW.html files only."""
    v = _run(
        _page(
            "<p>We pooled NCT01035255 with NCT99999999 for mortality.</p>",
            _trial("NCT01035255"),
        ),
        name="index.html",
    )
    assert v == [], "out-of-scope filename must produce nothing; got %r" % (v,)
