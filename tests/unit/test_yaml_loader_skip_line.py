"""Tests for the sentinel:skip-line per-line suppression marker.

Added 2026-04-16 late-night to drain narrow false-positive WARNs where
upstream guards aren't visible to the pattern matcher. Examples:

    # sentinel:skip-line P1-empty-dataframe-access
    value = df['col'].iloc[0]   # safe: guarded by len(df) >= 3 above

    value = df['col'].iloc[0]   # sentinel:skip-line P1-empty-dataframe-access

A bare `sentinel:skip-line` (no rule ID) suppresses all rules on the
line — use sparingly.
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.yaml_loader import load_yaml_rule


# Reuse the shipped P0-hardcoded-local-path rule for end-to-end testing —
# it has a concrete pattern and fires on any C:\Users\<name>\ reference.
RULE_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "yaml" / "P0-hardcoded-local-path.yaml"
)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _scan(tmp_path: Path):
    return load_yaml_rule(RULE_PATH).check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )


def test_no_marker_fires_normally(tmp_path: Path):
    _write(tmp_path / "src" / "bad.py", 'DATA = "C:/Users/user/data.csv"\n')
    assert len(_scan(tmp_path)) == 1


def test_same_line_scoped_marker_suppresses(tmp_path: Path):
    _write(tmp_path / "src" / "bad.py",
           'DATA = "C:/Users/user/data.csv"  # sentinel:skip-line P0-hardcoded-local-path\n')
    assert _scan(tmp_path) == []


def test_previous_line_scoped_marker_suppresses(tmp_path: Path):
    _write(tmp_path / "src" / "bad.py",
           '# sentinel:skip-line P0-hardcoded-local-path\n'
           'DATA = "C:/Users/user/data.csv"\n')
    assert _scan(tmp_path) == []


def test_bare_marker_suppresses_all(tmp_path: Path):
    _write(tmp_path / "src" / "bad.py",
           'DATA = "C:/Users/user/data.csv"  # sentinel:skip-line\n')
    assert _scan(tmp_path) == []


def test_marker_for_different_rule_does_not_suppress(tmp_path: Path):
    _write(tmp_path / "src" / "bad.py",
           'DATA = "C:/Users/user/data.csv"  # sentinel:skip-line P1-some-other-rule\n')
    assert len(_scan(tmp_path)) == 1


def test_marker_two_lines_above_does_not_suppress(tmp_path: Path):
    _write(tmp_path / "src" / "bad.py",
           '# sentinel:skip-line P0-hardcoded-local-path\n'
           'x = 1\n'
           'DATA = "C:/Users/user/data.csv"\n')
    # Marker is 2 lines above the match — NOT suppressed (only same line
    # or immediate prev line counts; prevents loose scoping).
    assert len(_scan(tmp_path)) == 1


def test_multiple_rule_ids_comma_separated(tmp_path: Path):
    _write(tmp_path / "src" / "bad.py",
           'DATA = "C:/Users/user/data.csv"  # sentinel:skip-line P1-other, P0-hardcoded-local-path\n')
    assert _scan(tmp_path) == []


def test_multiple_rule_ids_space_separated(tmp_path: Path):
    _write(tmp_path / "src" / "bad.py",
           'DATA = "C:/Users/user/data.csv"  # sentinel:skip-line P1-other P0-hardcoded-local-path\n')
    assert _scan(tmp_path) == []
