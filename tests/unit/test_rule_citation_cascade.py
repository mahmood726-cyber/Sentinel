# sentinel:skip-file — fixtures contain example malformed DOI strings.
"""Tests for P0-citation-cascade DOI validation.

Focus: the 2026-05-28 E156-placeholder allowance (10.156/<slug>) plus
the core contract — malformed real-DOI attempts still BLOCK, valid
DOIs pass.
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "citation_cascade.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def _doi_blocks(verdicts):
    return [v for v in verdicts
            if v.severity == Severity.BLOCK and "DOI" in v.detail]


def test_e156_placeholder_doi_suppressed(tmp_path):
    """10.156/<slug> is the E156 capsule pre-registration convention —
    must not BLOCK. Regression for AfricaRCT's 134-capsule cluster."""
    (tmp_path / "capsule_e156.md").write_text(
        "# Capsule\n\nSome body.\n\n## Note Block\n\n"
        "- DOI: 10.156/administrative-pi\n",
        encoding="utf-8",
    )
    assert _doi_blocks(_rule().check(_ctx(tmp_path))) == []


def test_e156_placeholder_various_slugs(tmp_path):
    """Variable suffixes all suppressed — it's a namespace, not a value."""
    (tmp_path / "a.md").write_text("DOI: 10.156/angle-12_site-clustering\n", encoding="utf-8")
    (tmp_path / "b.md").write_text("doi: 10.156/altruism-efficiency\n", encoding="utf-8")
    assert _doi_blocks(_rule().check(_ctx(tmp_path))) == []


def test_real_malformed_doi_still_blocks(tmp_path):
    """A genuinely malformed real-DOI attempt (3-digit registrant that
    ISN'T the 156 convention) must still BLOCK."""
    (tmp_path / "ref.md").write_text(
        "See doi: 10.999/some-suffix for details\n", encoding="utf-8"
    )
    blocks = _doi_blocks(_rule().check(_ctx(tmp_path)))
    assert len(blocks) >= 1


def test_valid_doi_passes(tmp_path):
    """A well-formed DOI (10.<4+ digits>/suffix) must not BLOCK."""
    (tmp_path / "ref.md").write_text(
        "Reference: https://doi.org/10.1136/bmj.n2387\n", encoding="utf-8"
    )
    assert _doi_blocks(_rule().check(_ctx(tmp_path))) == []


def test_existing_placeholder_values_still_pass(tmp_path):
    """The pre-existing enumerated placeholders (10.x/y) keep passing."""
    (tmp_path / "ref.md").write_text(
        "DOI: 10.x/y\nDOI: pending\n", encoding="utf-8"
    )
    assert _doi_blocks(_rule().check(_ctx(tmp_path))) == []
