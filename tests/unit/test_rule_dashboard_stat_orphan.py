"""Tests for P2-dashboard-stat-orphan.

In an HTML file, a `<div class="num">X%</div>` whose value appears NOWHERE
else in the document is a likely stat-card-stale bug: the narrative said
one number, the stat card said another, and after an update the narrative
was refreshed but the stat card was missed.

Triggering incident: shifaa 2026-04-16. Narrative "<strong>61.7% of the
HIC-LMIC trial gap</strong> is explained by covariate differences" lived
next to stat-card "<div class='num'>85%</div> Gap explained by endowments"
— same concept, two different numbers. The stat-card 85% appeared only
once in the file, which would have been the hint.

Severity: INFO (not WARN or BLOCK). Legitimate orphan KPIs exist (stat
cards often show unique headline numbers not reprised in prose). INFO
surfaces for review without gating.
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "dashboard_stat_orphan.py"
)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_no_html_no_verdict(tmp_path: Path):
    _write(tmp_path / "notes.md", "some markdown")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_stat_card_value_reprised_in_narrative_clean(tmp_path: Path):
    _write(tmp_path / "dash.html", """
<html><body>
  <p>The analysis found <strong>61.7%</strong> of the gap explained.</p>
  <div class="stat-card"><div class="num">61.7%</div><div class="label">Gap</div></div>
</body></html>
""")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_orphan_stat_card_pct_flagged(tmp_path: Path):
    # Stat card says 85% but narrative says 61.7% — orphan.
    _write(tmp_path / "dash.html", """
<html><body>
  <p>The analysis found <strong>61.7%</strong> of the gap explained.</p>
  <div class="stat-card"><div class="num">85%</div><div class="label">Gap</div></div>
</body></html>
""")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.rule_id == "P2-dashboard-stat-orphan"
    assert v.severity == Severity.INFO
    assert "85%" in v.detail


def test_multiple_orphans_multi_verdict(tmp_path: Path):
    _write(tmp_path / "dash.html", """
<html><body>
  <p>Narrative value: <strong>50%</strong></p>
  <div class="stat-card"><div class="num">50%</div><div class="label">Matches</div></div>
  <div class="stat-card"><div class="num">99%</div><div class="label">Orphan A</div></div>
  <div class="stat-card"><div class="num">1.5x</div><div class="label">Orphan B</div></div>
</body></html>
""")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    # 99% and 1.5x are orphans; 50% is reprised
    orphans = sorted(v.detail for v in verdicts)
    assert any("99%" in d for d in orphans)
    assert any("1.5x" in d for d in orphans)
    assert not any("50%" in d for d in orphans)


def test_bare_integer_orphan_not_flagged(tmp_path: Path):
    # A stat-card <div class="num">42</div> (no unit suffix) is too easy
    # to false-positive on prose ("42 different countries..."). Skip.
    _write(tmp_path / "dash.html", """
<html><body>
  <div class="stat-card"><div class="num">42</div><div class="label">Items</div></div>
</body></html>
""")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_large_number_with_comma_reprised(tmp_path: Path):
    # Check that comma-formatted numbers (74,881) are detected consistently
    _write(tmp_path / "dash.html", """
<html><body>
  <p>We analysed 74,881 trials.</p>
  <div class="stat-card"><div class="num">74,881</div><div class="label">Trials</div></div>
</body></html>
""")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    # "74,881" doesn't have a %/x suffix so rule doesn't check it. No verdict.
    assert rule.check(ctx) == []


def test_excluded_dirs_skipped(tmp_path: Path):
    _write(tmp_path / "node_modules" / "pkg" / "demo.html", """
<div class="stat-card"><div class="num">99%</div></div>
""")
    _write(tmp_path / "dist" / "out.html", """
<div class="stat-card"><div class="num">99%</div></div>
""")
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_portfolio_scope_inactive(tmp_path: Path):
    _write(tmp_path / "dash.html", """
<div class="stat-card"><div class="num">99%</div></div>
""")
    pi = tmp_path / "pi"
    pi.mkdir()
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    assert rule.check(ctx) == []
