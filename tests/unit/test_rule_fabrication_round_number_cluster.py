"""Tests for P1-fabrication-round-number-cluster.

This rule had NO test: mutation testing on 2026-08-30 replaced its `check()`
with `return []` and the suite stayed green, so its destruction was invisible.

What it guards (E156 Assurance Standard, "fabrication-detection family"):
  - three or more distinct suspicious round-number categories clustered in one
    workbook entry block or root-level *_REVIEW.html body.

Assertions state the REQUIREMENT (a same-body cluster of suspicious round
number categories must WARN), not the current message text, so rewording the
detail does not break them. The positive has a matching negative so the rule
cannot be "fixed" by firing on everything.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "fabrication_round_number_cluster.py"
)

RULE_ID = "P1-fabrication-round-number-cluster"


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _review_page(body: str) -> str:
    """A minimal root-level review page carrying one body of quoted evidence."""
    return "<html><body>\n" + body + "\n</body></html>"


def _run(body: str, name: str = "HFREF_NMA_REVIEW.html"):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / name).write_text(body, encoding="utf-8")
        return _rule().check(RepoContext(repo_root=p, mode=ScanMode.REPO))


def _warns(v):
    return [x for x in v if x.severity == Severity.WARN]


def test_severity_is_warn():
    """Round-number clustering is a fabrication warning, not a push block."""
    assert _rule().severity == Severity.WARN


def test_warns_on_three_round_number_categories_in_review_body():
    """A same-body cluster of tidy cohort, p-value, and follow-up values must WARN."""
    v = _run(_review_page(
        "The trial reported n=200 participants, p=0.001, and "
        "follow-up 12.0 months."
    ))

    warns = _warns(v)
    assert len(warns) >= 1, "three round-number categories must WARN; got %r" % (v,)
    assert any(x.rule_id == RULE_ID for x in warns), "WARN must use %s; got %r" % (
        RULE_ID,
        warns,
    )


def test_does_not_warn_on_irregular_review_numbers():
    """Negative control: realistic irregular values must stay silent."""
    v = _run(_review_page(
        "The trial reported n=143 participants, p=0.038, OR=0.78, "
        "follow-up 13.7 months, and 47.3% improved."
    ))

    assert _warns(v) == [], "irregular values must not WARN; got %r" % (_warns(v),)
