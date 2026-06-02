"""Tests for the local 'no naked numbers' path of P2-hallucination-classifier.

Flags an effect estimate / p-value in a CURRENT BODY whose value is absent from
that entry's evidence (DATA + references). No API; deterministic.
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode
from sentinel.registry.plugin_loader import load_plugin_rule

PLUGIN = (Path(__file__).parent.parent.parent
          / "sentinel" / "rules" / "plugins" / "hallucination_classifier.py")


def _rule():
    return load_plugin_rule(PLUGIN)


def _ctx(p: Path) -> RepoContext:
    return RepoContext(repo_root=p, mode=ScanMode.REPO)


def _workbook(tmp_path: Path, body: str, data: str) -> None:
    (tmp_path / "rewrite-workbook.txt").write_text(
        f"[1/1] Test trial\n"
        f"DATA: {data}\n\n"
        f"CURRENT BODY (editable)\n{body}\n\n"
        f"YOUR REWRITE\nplaceholder\n",
        encoding="utf-8",
    )


def test_supported_number_no_finding(tmp_path):
    # Body's HR 0.72 + CI bounds all appear in DATA → supported → silent.
    _workbook(
        tmp_path,
        body="The drug reduced mortality (HR 0.72, 95% CI 0.61-0.85; p=0.003).",
        data="HR 0.72 (95% CI 0.61-0.85), p=0.003",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_naked_number_fires(tmp_path):
    # Body asserts HR 0.50 (and CI 0.40) absent from the DATA evidence → flag.
    _workbook(
        tmp_path,
        body="The drug halved mortality (HR 0.50, 95% CI 0.40-0.60).",
        data="HR 0.72 (95% CI 0.61-0.85), p=0.003",
    )
    assert len(_rule().check(_ctx(tmp_path))) >= 1


def test_no_workbook_no_finding(tmp_path):
    assert _rule().check(_ctx(tmp_path)) == []
