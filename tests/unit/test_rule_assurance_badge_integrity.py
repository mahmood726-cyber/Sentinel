# sentinel:skip-file — fixtures contain deliberately forged badge JSON.
"""Tests for P1-assurance-badge-integrity."""
from __future__ import annotations

import json
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "assurance_badge_integrity.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(p: Path) -> RepoContext:
    return RepoContext(repo_root=p, mode=ScanMode.REPO)


def _write_badge(tmp_path: Path, checks: dict, tier: str) -> None:
    sub = tmp_path / "e156-submission"
    sub.mkdir(exist_ok=True)
    (sub / "assurance.json").write_text(
        json.dumps({"checks": checks, "tier": tier}), encoding="utf-8"
    )


# checks that legitimately compute to "none" (data_file_present not-run)
_NONE_CHECKS = {
    "citation_cascade": "pass", "data_file_present": "not-run",
    "code_runs": "not-run", "dashboard_match": "not-run",
    "claim_language": "pass", "analysis_rerun": "not-run",
    "external_review": "not-run", "denominator_logic": "pass",
}


def test_consistent_badge_clean(tmp_path):
    _write_badge(tmp_path, _NONE_CHECKS, "none")
    assert _rule().check(_ctx(tmp_path)) == []


def test_forged_gold_flagged(tmp_path):
    _write_badge(tmp_path, _NONE_CHECKS, "gold")
    vs = _rule().check(_ctx(tmp_path))
    assert len(vs) == 1
    assert "forged or stale" in vs[0].detail


def test_malformed_json_flagged(tmp_path):
    (tmp_path / "assurance.json").write_text("{not valid json", encoding="utf-8")
    vs = _rule().check(_ctx(tmp_path))
    assert len(vs) == 1
    assert "not valid JSON" in vs[0].detail


def test_no_badge_is_inert(tmp_path):
    (tmp_path / "readme.md").write_text("nothing here\n", encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_skip_marker_ignored(tmp_path):
    (tmp_path / "assurance.json").write_text(
        "sentinel:skip-file\n" + json.dumps({"checks": _NONE_CHECKS, "tier": "gold"}),
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_block_opt_in(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_ASSURANCE_BADGE_BLOCK", "1")
    _write_badge(tmp_path, _NONE_CHECKS, "gold")
    rule = load_plugin_rule(PLUGIN_PATH)  # reload so the module-level flag is re-read
    vs = rule.check(_ctx(tmp_path))
    assert len(vs) == 1
    assert vs[0].severity == Severity.BLOCK
