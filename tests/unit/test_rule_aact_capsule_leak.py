"""Tests for P1-aact-capsule-leak.

This rule had NO test: mutation testing on 2026-08-30 replaced its `check()`
with `return []` and the suite stayed green, so its destruction was invisible.
It is the Layer-3 net behind the AACT capsule generator's Python-to-JS value
encoding and emit-time guard.

What it guards (lessons.md 2026-05-24 rapidmeta placeholder leak):
  - bare Python `None` values leaked into the `const CAPSULE = {...};` payload;
  - `NaN` and `Infinity` literals in that payload;
  - residual `__AACT_*` template tokens;
  - rendered prose such as "with n participants" or "None trials".

Assertions state the REQUIREMENT (a capsule payload/prose placeholder leak must
warn), not the current message text, so rewording the detail does not break
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
    / "sentinel" / "rules" / "plugins" / "aact_capsule_leak.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _page(payload: str, prose: str = "This capsule has 128 participants.") -> str:
    """A minimal AACT capsule page carrying the scanned CAPSULE literal."""
    return (
        "<html><body>\n"
        f"<p>{prose}</p>\n"
        "<script>\n"
        f"const CAPSULE = {payload};\n"
        "</script>\n"
        "</body></html>"
    )


def _run(body: str, name: str = "hfref-capsule.html"):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / name).write_text(body, encoding="utf-8")
        return _rule().check(RepoContext(repo_root=p, mode=ScanMode.REPO))


def _warns(v):
    return [x for x in v if x.rule_id == "P1-aact-capsule-leak" and x.severity == Severity.WARN]


# --------------------------------------------------------------- severity


def test_severity_is_warn():
    """Capsule placeholder leaks warn by default."""
    assert _rule().severity == Severity.WARN


# ---------------------------------------------------------- payload leaks


def test_warns_on_bare_none_in_capsule_payload():
    """A Python None literal inside the CAPSULE payload is invalid JS output."""
    v = _run(_page('{"nct_id": "NCT01035255", "arms": [None]}'))
    assert len(_warns(v)) >= 1, "bare None in CAPSULE payload must WARN; got %r" % (v,)


def test_does_not_warn_on_clean_capsule_payload():
    """Negative control: a complete scoped capsule must stay silent."""
    v = _run(_page('{"nct_id": "NCT01035255", "arms": [{"name": "drug", "n": 128}]}'))
    assert v == [], "clean capsule payload must produce nothing; got %r" % (v,)


# --------------------------------------------------------------- scoping


def test_ignores_unrelated_html_filename():
    """Scope is *-capsule.html; other pages are out of scope."""
    v = _run(_page('{"nct_id": "NCT01035255", "arms": [None]}'), name="index.html")
    assert v == [], "out-of-scope filename must produce nothing; got %r" % (v,)
