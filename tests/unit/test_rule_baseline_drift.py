"""Tests for P0-baseline-drift.

Skip the "report drift blocks push" path if mission_critical isn't
installed on the runner. The no-baseline-json / warn-on-import-failure
paths always run.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "baseline_drift.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def _mission_critical_available() -> bool:
    try:
        import mission_critical  # noqa: F401
        return True
    except ImportError:
        return False


_HAS_MC = _mission_critical_available()


def test_no_baseline_json_is_silent(tmp_path: Path):
    (tmp_path / "README.md").write_text("hi", encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


@pytest.mark.skipif(
    _HAS_MC,
    reason="mission_critical IS installed here; see test_drift_blocks for actual drift check",
)
def test_missing_mission_critical_produces_warn(tmp_path: Path):
    (tmp_path / "baseline.json").write_text(
        '{"schema_version": "0.1", "records": {}}', encoding="utf-8"
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.WARN
    assert "mission_critical" in verdicts[0].detail


def test_malformed_baseline_json_blocks(tmp_path: Path):
    (tmp_path / "baseline.json").write_text("not json{", encoding="utf-8")
    verdicts = _rule().check(_ctx(tmp_path))
    # Either a RuntimeError BLOCK (if MC installed) or a WARN on import
    assert len(verdicts) == 1


@pytest.mark.skipif(
    not _HAS_MC, reason="requires mission_critical installed",
)
def test_matching_report_no_drift_silent(tmp_path: Path):
    from mission_critical.baseline import BaselineStore
    store = BaselineStore(tmp_path / "baseline.json")
    store.record(
        "paper-1",
        pooled_estimate=-0.223,
        ci_lower=-0.311,
        ci_upper=-0.135,
        k=5,
    )
    store.save()
    # Matching report
    (tmp_path / "paper-1.report.json").write_text(json.dumps({
        "pooled_estimate": -0.223,
        "ci_lower": -0.311,
        "ci_upper": -0.135,
        "k": 5,
    }), encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


@pytest.mark.skipif(
    not _HAS_MC, reason="requires mission_critical installed",
)
def test_drift_beyond_tolerance_blocks(tmp_path: Path):
    from mission_critical.baseline import BaselineStore
    store = BaselineStore(tmp_path / "baseline.json")
    store.record("paper-1", pooled_estimate=-0.223)
    store.save()
    # Drifted report: 0.01 difference, way over 1e-6
    (tmp_path / "paper-1.report.json").write_text(json.dumps({
        "pooled_estimate": -0.213,
    }), encoding="utf-8")
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.BLOCK
    assert "paper-1" in verdicts[0].detail
    assert "drift" in verdicts[0].detail.lower()


@pytest.mark.skipif(
    not _HAS_MC, reason="requires mission_critical installed",
)
def test_drift_under_tolerance_silent(tmp_path: Path):
    from mission_critical.baseline import BaselineStore
    store = BaselineStore(tmp_path / "baseline.json")
    store.record("paper-1", pooled_estimate=-0.223)
    store.save()
    # Drift under 1e-6
    (tmp_path / "paper-1.report.json").write_text(json.dumps({
        "pooled_estimate": -0.223 + 1e-10,
    }), encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


@pytest.mark.skipif(
    not _HAS_MC, reason="requires mission_critical installed",
)
def test_paper_in_baseline_but_no_report_silent(tmp_path: Path):
    """Paper recorded in baseline but no matching report on this push
    -> nothing to check, silent (not a violation)."""
    from mission_critical.baseline import BaselineStore
    store = BaselineStore(tmp_path / "baseline.json")
    store.record("paper-1", pooled_estimate=-0.223)
    store.save()
    # No paper-1.report.json
    assert _rule().check(_ctx(tmp_path)) == []


@pytest.mark.skipif(
    not _HAS_MC, reason="requires mission_critical installed",
)
def test_unwraps_diffmeta_report_shape(tmp_path: Path):
    """A diffmeta JSON output has nested `python`/`r` keys; plugin
    should extract the python block and match against baseline."""
    from mission_critical.baseline import BaselineStore
    store = BaselineStore(tmp_path / "baseline.json")
    store.record("paper-1", pooled_estimate=-0.223)
    store.save()
    # diffmeta-shape report (with nested python and drifted value)
    (tmp_path / "paper-1.report.json").write_text(json.dumps({
        "python": {
            "estimate": -0.213,  # drifted by 0.01
            "se": 0.044,
            "ci_lower": -0.30, "ci_upper": -0.126,
            "k": 5,
        },
        "r": {"estimate": -0.213},
        "diverges": False,
    }), encoding="utf-8")
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.BLOCK
