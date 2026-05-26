# sentinel:skip-file — test fixtures literally contain mojibake patterns.
"""Tests for P1-cp1252-mojibake.

Fires on UTF-8 files containing canonical cp1252-misread byte
sequences. Past incident: lessons.md "cp1252 save corruption — detect
via mojibake" (EvidenceOracle 2026-04-16). The file opens fine; git
diff drowns under encoding noise around the real change.
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "cp1252_mojibake.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def test_severity_is_warn(tmp_path):
    """Warn — the file READS fine; corruption is a diff-noise/integrity
    issue, not a runtime crash."""
    assert _rule().severity == Severity.WARN


def test_fires_on_box_drawing_mojibake(tmp_path):
    """`â”€` is the cp1252-misread of `─` (U+2500)."""
    (tmp_path / "bad.md").write_text("# x\nâ”€â”€â”€\n", encoding="utf-8")
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert verdicts[0].file == "bad.md"
    assert "mojibake" in verdicts[0].detail.lower()


def test_fires_on_em_dash_mojibake(tmp_path):
    """The real em-dash mojibake bytes: UTF-8 0xE2 0x80 0x94 read as cp1252
    yields U+00E2 + U+20AC + U+201D. V1 fixture had ASCII " (U+0022) as the
    3rd char which never actually appears in real corruption."""
    em_dash_mojibake = "—".encode("utf-8").decode("cp1252")
    (tmp_path / "bad.py").write_text(
        f'"""Docs {em_dash_mojibake} but"""\n', encoding="utf-8"
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert verdicts[0].file == "bad.py"
    # New algorithmic detection includes the recovered original char.
    assert "—" in verdicts[0].detail or "EM DASH" in verdicts[0].detail


def test_quiet_on_clean_utf8(tmp_path):
    """Real em-dash, real arrow, real star — no mojibake."""
    (tmp_path / "good.md").write_text(
        "clean: — → ★ and box: ─ ─ ─\n", encoding="utf-8"
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_legitimate_french(tmp_path):
    """`â` in legitimate French (câble, âgé) must not trigger — only
    `â` followed by specific punctuation/symbol bytes counts."""
    (tmp_path / "good.md").write_text("Le câble est âgé.\n", encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_files_without_a_circumflex(tmp_path):
    """The cheap pre-filter (`â` not in text → skip) is the fast path
    that keeps the rule cheap on a 3000-file repo."""
    (tmp_path / "plain.txt").write_text("ASCII only here.\n", encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_count_reported_in_detail(tmp_path):
    """Detail message includes the total mojibake count so operators
    know whether to revert or surgically fix."""
    # Use explicit unicode escapes — plain `'` in Python source is ASCII
    # U+0027 (1-byte UTF-8), not curly U+2019 (3-byte E2 80 99). Only
    # 3-byte UTF-8 chars in U+2000–U+27FF can mojibake via cp1252 round-trip.
    chars = "─’★"   # ─ ' ★
    seq = "".join(c.encode("utf-8").decode("cp1252") for c in chars)
    (tmp_path / "bad.md").write_text(f"{seq}\n", encoding="utf-8")
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert "3 total recoverable" in verdicts[0].detail
