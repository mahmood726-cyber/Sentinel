# sentinel:skip-file — fixtures contain example overclaim phrasings.
"""Tests for the comparative-confidence tier of claim_language (Track D).

Catches intensifier+verb / strong-evidence overclaims that use no banned
trigger word, while leaving legitimate statistical-significance reporting and
hedged language alone.
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "claim_language.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(p: Path) -> RepoContext:
    return RepoContext(repo_root=p, mode=ScanMode.REPO)


def _students(tmp_path: Path, html: str) -> None:
    (tmp_path / "students.html").write_text(html, encoding="utf-8")


def _comparative(verdicts):
    return [v for v in verdicts if "comparative-confidence" in v.detail]


def test_intensifier_plus_verb_warns(tmp_path):
    _students(tmp_path, "<html><body><p>The drug clearly reduces mortality.</p></body></html>")
    assert _comparative(_rule().check(_ctx(tmp_path)))


def test_strong_evidence_phrase_warns(tmp_path):
    _students(tmp_path, "<html><body><p>There was a strong signal of benefit.</p></body></html>")
    assert _comparative(_rule().check(_ctx(tmp_path)))


def test_significant_reduction_is_not_comparative_overclaim(tmp_path):
    # statistical-significance reporting is legitimate result-sentence language
    _students(tmp_path, "<html><body><p>Mortality was significantly reduced (RR 0.80, 95% CI 0.70-0.91).</p></body></html>")
    assert _comparative(_rule().check(_ctx(tmp_path))) == []


def test_hedged_language_stays_clean(tmp_path):
    _students(tmp_path, "<html><body><p>The intervention was associated with lower mortality, consistent with prior trials.</p></body></html>")
    assert _rule().check(_ctx(tmp_path)) == []


def test_override_marker_suppresses(tmp_path):
    _students(
        tmp_path,
        "<!-- sentinel:claim-language-allow -->\n"
        "<html><body><p>clearly reduces mortality</p></body></html>",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_comparative_tier_stays_warn_under_block_optin(tmp_path, monkeypatch):
    # The comparative tier is intentionally hardcoded WARN even when the
    # workbook BLOCK opt-in is on (it is a higher-FP heuristic). Lock that so a
    # future refactor can't silently start BLOCKing real prose.
    monkeypatch.setenv("SENTINEL_CLAIM_LANGUAGE_BLOCK", "1")
    (tmp_path / "rewrite-workbook.txt").write_text(
        "[1/1] Demo\nThe drug clearly reduces mortality across all subgroups.\n",
        encoding="utf-8",
    )
    rule = load_plugin_rule(PLUGIN_PATH)  # reload so the env flag is read
    comp = [v for v in rule.check(_ctx(tmp_path)) if "comparative-confidence" in v.detail]
    assert comp
    assert all(v.severity == Severity.WARN for v in comp)
