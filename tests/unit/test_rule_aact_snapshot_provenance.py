"""Tests for P0-aact-snapshot-provenance.

This rule had NO effective test: mutation testing on 2026-08-30 replaced its
`check()` with `return []` and the suite stayed green, so its destruction was
invisible.

What it guards:
  - AACT/ClinicalTrials.gov capsule pages must carry a non-empty
    `snapshot_date` in their embedded CAPSULE JSON.
  - rendered capsule prose must not claim live freshness unless it cites the
    fixed snapshot context.

Assertions state the REQUIREMENT (a capsule with missing snapshot provenance
must block), not the current message text, so rewording the detail does not
break them. Every positive has a matching negative so the rule cannot be
"fixed" by firing on everything.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "aact_snapshot_provenance.py"
)
RULE_ID = "P0-aact-snapshot-provenance"


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _capsule(snapshot_date: str, rendered_prose: str = "") -> str:
    """A minimal *-capsule.html page carrying parsed CAPSULE JSON."""
    return (
        "<html><body>\n"
        f"<main>{rendered_prose}</main>\n"
        "<script>\n"
        "const CAPSULE = {\n"
        '  "title": "AACT capsule fixture",\n'
        f'  "snapshot_date": "{snapshot_date}"\n'
        "};\n"
        "</script>\n"
        "</body></html>"
    )


def _run(body: str, name: str = "trial-capsule.html"):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / name).write_text(body, encoding="utf-8")
        return _rule().check(RepoContext(repo_root=p, mode=ScanMode.REPO))


def _blocks(v):
    return [x for x in v if x.severity == Severity.BLOCK]


# --------------------------------------------------------------- severity


def test_severity_is_block():
    """Missing AACT snapshot provenance is not a style issue."""
    assert _rule().severity == Severity.BLOCK


# --------------------------------------------------------- snapshot field


def test_blocks_capsule_json_missing_snapshot_date():
    """A parsed capsule with no snapshot_date cannot cite its AACT vintage."""
    v = _run(_capsule(""))
    assert any(
        x.rule_id == RULE_ID and x.severity == Severity.BLOCK for x in v
    ), "missing snapshot_date must BLOCK; got %r" % (v,)


def test_does_not_block_capsule_json_with_snapshot_date():
    """Negative control: a parsed capsule with a snapshot date is clean."""
    v = _run(_capsule("2026-03-29"))
    assert v == [], "capsule with snapshot_date must produce nothing; got %r" % (v,)


# ------------------------------------------------------- freshness claims


def test_blocks_live_freshness_claim_without_snapshot_reference():
    """Rendered capsule prose must not claim live freshness for fixed data."""
    prose = "This capsule is always current. " + ("Fixed data vintage. " * 20)
    v = _run(_capsule("2026-03-29", rendered_prose=prose))
    assert any(
        x.rule_id == RULE_ID and x.severity == Severity.BLOCK for x in v
    ), "live freshness claim must BLOCK; got %r" % (v,)


def test_does_not_block_live_claim_inside_script():
    """The rendered-prose check must ignore matching text inside scripts."""
    v = _run(
        _capsule("2026-03-29")
        + "\n<script>const message = 'always current';</script>\n"
    )
    assert v == [], "script-only freshness text must produce nothing; got %r" % (v,)


# --------------------------------------------------------------- scoping


def test_ignores_unrelated_html_filename():
    """Scope is only *-capsule.html files."""
    v = _run(_capsule(""), name="index.html")
    assert v == [], "out-of-scope filename must produce nothing; got %r" % (v,)
