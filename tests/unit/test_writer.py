from datetime import datetime, timezone
from pathlib import Path
from sentinel.core import Severity, Verdict
from sentinel.io.writer import write_findings


def _v(severity: Severity, rule_id: str) -> Verdict:
    return Verdict(
        rule_id=rule_id,
        severity=severity,
        repo="C:/repo",
        file="a.py",
        line=1,
        detail="d",
        fix_hint="fh",
        source="src.md",
        timestamp=datetime(2026, 4, 14, 0, 0, 0, tzinfo=timezone.utc),
    )


def test_block_verdicts_write_stuck_failures(tmp_path: Path):
    verdicts = [_v(Severity.BLOCK, "R-block"), _v(Severity.WARN, "R-warn")]
    write_findings(tmp_path, verdicts)
    stuck = (tmp_path / "STUCK_FAILURES.md").read_text(encoding="utf-8")
    warn = (tmp_path / "review-findings.md").read_text(encoding="utf-8")
    assert "R-block" in stuck
    assert "R-warn" not in stuck
    assert "R-warn" in warn


def test_info_only_creates_no_files(tmp_path: Path):
    write_findings(tmp_path, [_v(Severity.INFO, "R-info")])
    assert not (tmp_path / "STUCK_FAILURES.md").exists()
    assert not (tmp_path / "review-findings.md").exists()


def test_empty_verdicts_creates_no_files(tmp_path: Path):
    write_findings(tmp_path, [])
    assert not (tmp_path / "STUCK_FAILURES.md").exists()
    assert not (tmp_path / "review-findings.md").exists()


def test_appends_to_existing_review_findings(tmp_path: Path):
    (tmp_path / "review-findings.md").write_text("# existing\n\n", encoding="utf-8")
    write_findings(tmp_path, [_v(Severity.WARN, "R-warn")])
    content = (tmp_path / "review-findings.md").read_text(encoding="utf-8")
    assert "# existing" in content
    assert "R-warn" in content
