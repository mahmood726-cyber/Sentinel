"""Tests for P0-localstorage-key-collision.

This rule had NO test naming it: mutation testing on 2026-08-30 replaced its
`check()` with `return []` and the suite stayed green, so localStorage prefix
collisions across dashboards were invisible.

What it guards:
  - two or more distinct `*_REVIEW.html` dashboards sharing the same
    canonical `rapid_meta_*` localStorage key prefix;
  - suffix variants such as `_v1_0` and `_theme` that still collapse to the
    same persisted-state namespace.

Assertions state the REQUIREMENT (distinct dashboards must not share a
localStorage namespace), not the current message text, so rewording the detail
does not break them. Every positive has a negative so the rule cannot be
"fixed" by firing on everything.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "localstorage_key_collision.py"
)
RULE_ID = "P0-localstorage-key-collision"


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _page(storage_key: str) -> str:
    """A minimal rapidmeta-style review page carrying one localStorage key."""
    return (
        "<html><script>\n"
        f"localStorage.setItem('{storage_key}', JSON.stringify({{included: []}}));\n"
        "</script></html>"
    )


def _run(files: dict[str, str]):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for rel, body in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        return _rule().check(RepoContext(repo_root=root, mode=ScanMode.REPO))


def _blocks(verdicts):
    return [
        verdict
        for verdict in verdicts
        if verdict.rule_id == RULE_ID and verdict.severity == Severity.BLOCK
    ]


def test_severity_is_block():
    """A storage collision can corrupt persisted review state."""
    rule = _rule()
    assert rule.id == RULE_ID
    assert rule.severity == Severity.BLOCK


def test_blocks_shared_rapid_meta_prefix_across_distinct_dashboards():
    """Distinct dashboard basenames must not share one persisted-state prefix."""
    verdicts = _run({
        "VOCLOSPORIN_LN_REVIEW.html": _page("rapid_meta_collision_case_v1_0"),
        "SPARSENTAN_IGAN_REVIEW.html": _page("rapid_meta_collision_case_theme"),
    })

    blocks = _blocks(verdicts)
    assert len(blocks) == 2, "shared canonical prefix must BLOCK both files; got %r" % (verdicts,)
    assert {block.file for block in blocks} == {
        "VOCLOSPORIN_LN_REVIEW.html",
        "SPARSENTAN_IGAN_REVIEW.html",
    }


def test_allows_distinct_rapid_meta_prefixes():
    """Negative control: independent dashboard prefixes must stay silent."""
    verdicts = _run({
        "FINERENONE_HF_REVIEW.html": _page("rapid_meta_finerenone_hf_v1_0"),
        "ANIFROLUMAB_SLE_REVIEW.html": _page("rapid_meta_anifrolumab_sle_v1_0"),
    })

    assert _blocks(verdicts) == [], "distinct prefixes must not BLOCK; got %r" % (_blocks(verdicts),)


def test_allows_submission_mirror_with_same_basename():
    """A top-level dashboard and its submission mirror are the same basename."""
    verdicts = _run({
        "DAPA_HF_REVIEW.html": _page("rapid_meta_dapa_hf_v1_0"),
        "e156-submission/assets/DAPA_HF_REVIEW.html": _page("rapid_meta_dapa_hf_v1_0"),
    })

    assert _blocks(verdicts) == [], "same-basename mirrors must not BLOCK; got %r" % (_blocks(verdicts),)
