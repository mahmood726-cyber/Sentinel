"""Tests for P0-rapidmeta-data-integrity.

This rule had NO test: mutation testing on 2026-08-30 replaced its `check()`
with `return []` and the suite stayed green, so its destruction was invisible.

What it guards (RapidMeta dashboard data integrity):
  - duplicate NCT keys inside `realData`, where JS silently keeps the last one;
  - duplicate trial acronyms mapped to more than one NCT;
  - duplicate top-level fields in a trial header;
  - mismatch between an NCT's `realData.name` and `nctAcronyms` entry.

Assertions state the REQUIREMENT (silent object-literal shadowing must block),
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
    / "sentinel" / "rules" / "plugins" / "rapidmeta_data_integrity.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _page(real_data_entries: str, nct_acronyms: str) -> str:
    """A minimal rapidmeta-style review page carrying realData and acronyms."""
    return (
        "<html><script>\n"
        "const nctAcronyms = {\n"
        + nct_acronyms
        + "\n};\n"
        "const realData = {\n"
        + real_data_entries
        + "\n};\n"
        "</script></html>"
    )


def _run(body: str, name: str = "GA_REVIEW.html"):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / name).write_text(body, encoding="utf-8")
        return _rule().check(RepoContext(repo_root=p, mode=ScanMode.REPO))


def _blocks(v):
    return [x for x in v if x.severity == Severity.BLOCK]


def test_severity_is_block():
    """Silent data shadowing must stop a push."""
    assert _rule().severity == Severity.BLOCK


def test_blocks_duplicate_realdata_nct_key():
    """Two realData entries with the same NCT key silently shadow in JS."""
    v = _run(_page(
        "  'NCT01234567': { name: 'OAKS', pmid: '11111111', tE: 8, tN: 100, cE: 9, cN: 100 },\n"
        "  'NCT01234567': { name: 'OAKS', pmid: '22222222', tE: 10, tN: 100, cE: 11, cN: 100 }",
        "  'NCT01234567': 'OAKS'",
    ))

    blocks = _blocks(v)
    assert len(blocks) >= 1, "duplicate realData NCT key must BLOCK; got %r" % (v,)
    assert any(x.rule_id == "P0-rapidmeta-data-integrity" for x in blocks)


def test_does_not_block_unique_realdata_entries():
    """Negative control: unique NCT keys with matching acronyms must stay silent."""
    v = _run(_page(
        "  'NCT01234567': { name: 'OAKS', pmid: '11111111', tE: 8, tN: 100, cE: 9, cN: 100 },\n"
        "  'NCT07654321': { name: 'DERBY', pmid: '22222222', tE: 10, tN: 100, cE: 11, cN: 100 }",
        "  'NCT01234567': 'OAKS',\n"
        "  'NCT07654321': 'DERBY'",
    ))

    assert v == [], "unique realData entries must produce nothing; got %r" % (v,)
