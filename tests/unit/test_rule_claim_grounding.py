# sentinel:skip-file — fixtures contain example effect-claim strings without DOIs.
"""Tests for P1-claim-grounding: WARN on quantitative claims with no source locator."""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule

PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "claim_grounding.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def _warns(verdicts):
    return [v for v in verdicts if v.severity == Severity.WARN and v.rule_id == "P1-claim-grounding"]


def test_ungrounded_claim_warns(tmp_path):
    (tmp_path / "capsule.md").write_text(
        "# Result\n\nThe intervention reduced events (HR 0.74, 95% CI 0.65 to 0.85; p < 0.001).\n",
        encoding="utf-8",
    )
    assert len(_warns(_rule().check(_ctx(tmp_path)))) == 1


def test_claim_with_doi_is_cleared(tmp_path):
    (tmp_path / "capsule.md").write_text(
        "# Result\n\nThe intervention reduced events (HR 0.74, 95% CI 0.65 to 0.85).\n"
        "Source: doi:10.1056/NEJMoa1911303\n",
        encoding="utf-8",
    )
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_claim_with_nct_is_cleared(tmp_path):
    (tmp_path / "capsule.md").write_text(
        "RR 0.70 reported in NCT03036124.\n", encoding="utf-8"
    )
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_no_quantitative_claim_is_inert(tmp_path):
    (tmp_path / "notes.md").write_text(
        "# Plan\n\nWe will design a randomized trial and write a protocol.\n",
        encoding="utf-8",
    )
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_skip_marker_suppresses(tmp_path):
    (tmp_path / "fixture.md").write_text(
        "sentinel:skip-file\nHR 0.74 (95% CI 0.65 to 0.85)\n", encoding="utf-8"
    )
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_percent_reduction_claim_warns(tmp_path):
    (tmp_path / "c.md").write_text(
        "Treatment lowered hospitalization by 30% versus placebo.\n", encoding="utf-8"
    )
    assert len(_warns(_rule().check(_ctx(tmp_path)))) == 1
