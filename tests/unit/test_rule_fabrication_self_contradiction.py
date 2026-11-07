"""Tests for P1-fabrication-self-contradiction.

This rule had NO test: mutation testing on 2026-08-30 replaced its `check()`
with `return []` and the suite stayed green, so its destruction was invisible.

What it guards (E156 Assurance Standard, fabrication-detection family):
  - prose claiming "no difference" / "not significant" while a nearby ratio
    confidence interval is wholly above or below 1.00;
  - prose claiming no difference while a nearby absolute-difference confidence
    interval is wholly above or below 0.

Assertions state the REQUIREMENT (a null-result claim must not contradict its
own confidence interval), not the current message text, so rewording the detail
does not break them. Every positive has a matching negative so the rule cannot
be "fixed" by firing on everything.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "fabrication_self_contradiction.py"
)

RULE_ID = "P1-fabrication-self-contradiction"


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _review(body: str) -> str:
    """A minimal top-level review page in the plugin's scan scope."""
    return f"<html><body><p>{body}</p></body></html>"


def _run(body: str, name: str = "HFREF_NMA_REVIEW.html"):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / name).write_text(body, encoding="utf-8")
        return _rule().check(RepoContext(repo_root=p, mode=ScanMode.REPO))


def _warns(v):
    return [x for x in v if x.severity == Severity.WARN]


def test_severity_is_warn():
    """A self-contradictory interpretation is a warning-level fabrication signal."""
    assert _rule().severity == Severity.WARN


def test_warns_when_null_claim_contradicts_ratio_ci():
    """A no-difference claim is contradicted by a ratio CI wholly below 1.00."""
    v = _run(_review(
        "Across pooled trials there was no significant difference between "
        "groups (OR 0.55, 95% CI 0.42-0.68)."
    ))
    matching = [x for x in _warns(v) if x.rule_id == RULE_ID]
    assert len(matching) >= 1, (
        "null-result prose with a ratio CI wholly below 1.00 must WARN; got %r"
        % (v,)
    )


def test_does_not_warn_when_ratio_ci_brackets_null():
    """Negative control: a ratio CI that brackets 1.00 supports a null claim."""
    v = _run(_review(
        "Across pooled trials there was no significant difference between "
        "groups (OR 0.98, 95% CI 0.76-1.28)."
    ))
    assert _warns(v) == [], "ratio CI bracketing 1.00 must stay silent; got %r" % (v,)


def test_does_not_warn_on_significant_claim_with_significant_ratio_ci():
    """Negative control: the rule requires a nearby no-difference claim."""
    v = _run(_review(
        "Across pooled trials the intervention reduced events "
        "(RR 0.70, 95% CI 0.58-0.84)."
    ))
    assert v == [], "significant prose without a null claim must stay silent; got %r" % (v,)


def test_ignores_unrelated_html_filename():
    """Scope is *_REVIEW.html, students.html, and rewrite-workbook.txt."""
    v = _run(_review(
        "Across pooled trials there was no benefit (HR 1.40, 95% CI 1.18-1.66)."
    ), name="index.html")
    assert v == [], "out-of-scope filename must produce nothing; got %r" % (v,)
