"""Tests for size-capped log rotation (P1-5)."""
from __future__ import annotations

from pathlib import Path

from sentinel.io.rotation import rotate_if_needed, DEFAULT_MAX_BYTES
from sentinel.io import writer
from sentinel.core import Severity, Verdict
from datetime import datetime, timezone


def test_no_rotation_below_cap(tmp_path: Path):
    p = tmp_path / "log.md"
    p.write_text("small", encoding="utf-8")
    assert rotate_if_needed(p, max_bytes=1024) is False
    assert p.exists() and p.read_text() == "small"
    assert not (tmp_path / "log.md.1").exists()


def test_rotation_at_cap(tmp_path: Path):
    p = tmp_path / "log.md"
    p.write_text("x" * 200, encoding="utf-8")
    assert rotate_if_needed(p, max_bytes=100) is True
    # current file moved to .1; original path is now free for a fresh append
    assert not p.exists()
    assert (tmp_path / "log.md.1").read_text() == "x" * 200


def test_rotation_keeps_backup_count(tmp_path: Path):
    p = tmp_path / "log.jsonl"
    for marker in ("a", "b", "c", "d"):
        p.write_text(marker * 200, encoding="utf-8")
        rotate_if_needed(p, max_bytes=100, backup_count=2)
    # Only .1 and .2 survive; the oldest ("a") was dropped.
    assert (tmp_path / "log.jsonl.1").read_text() == "d" * 200
    assert (tmp_path / "log.jsonl.2").read_text() == "c" * 200
    assert not (tmp_path / "log.jsonl.3").exists()


def test_rotation_fail_soft_on_missing(tmp_path: Path):
    # Missing file never raises and never rotates.
    assert rotate_if_needed(tmp_path / "nope.md", max_bytes=1) is False


def test_env_override_max_bytes(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SENTINEL_LOG_MAX_BYTES", "50")
    p = tmp_path / "log.md"
    p.write_text("y" * 60, encoding="utf-8")
    assert rotate_if_needed(p) is True


def _verdict(sev: Severity) -> Verdict:
    return Verdict(
        rule_id="P0-test",
        severity=sev,
        repo="r",
        file="f.py",
        line=1,
        detail="d",
        fix_hint="h",
        source="s",
        timestamp=datetime.now(timezone.utc),
    )


def test_writer_rotates_oversized_block_log(tmp_path: Path, monkeypatch):
    """write_findings rotates an oversized STUCK_FAILURES.md before appending."""
    monkeypatch.setenv("SENTINEL_LOG_MAX_BYTES", "100")
    from sentinel.io.paths import BLOCK_MD
    big = tmp_path / BLOCK_MD
    big.write_text("z" * 200, encoding="utf-8")
    writer.write_findings(tmp_path, [_verdict(Severity.BLOCK)])
    # Old content rotated out; fresh file holds the header + new finding only.
    assert (tmp_path / f"{BLOCK_MD}.1").read_text().startswith("z")
    fresh = big.read_text()
    assert "z" * 200 not in fresh
    assert "P0-test" in fresh
