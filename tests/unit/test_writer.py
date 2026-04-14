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


def test_jsonl_mirrors_md_block_output(tmp_path: Path):
    """Each BLOCK verdict written to MD is also appended to STUCK_FAILURES.jsonl
    as a machine-readable line. Aggregators should prefer JSONL over regex-
    parsing MD."""
    import json
    verdicts = [_v(Severity.BLOCK, "R-block-1"), _v(Severity.BLOCK, "R-block-2")]
    write_findings(tmp_path, verdicts)

    jsonl_path = tmp_path / "STUCK_FAILURES.jsonl"
    assert jsonl_path.exists()
    lines = jsonl_path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert parsed[0]["rule_id"] == "R-block-1"
    assert parsed[0]["severity"] == "BLOCK"
    assert parsed[0]["file"] == "a.py"
    assert parsed[0]["line"] == 1
    assert parsed[0]["timestamp"] == "2026-04-14T00:00:00+00:00"
    assert parsed[1]["rule_id"] == "R-block-2"


def test_jsonl_mirrors_md_warn_output(tmp_path: Path):
    import json
    write_findings(tmp_path, [_v(Severity.WARN, "R-warn")])
    lines = (tmp_path / "review-findings.jsonl").read_text(encoding="utf-8").strip().split("\n")
    assert json.loads(lines[0])["rule_id"] == "R-warn"
    assert json.loads(lines[0])["severity"] == "WARN"


def test_jsonl_appends_across_runs(tmp_path: Path):
    """Two separate write_findings calls produce two lines in JSONL."""
    write_findings(tmp_path, [_v(Severity.BLOCK, "R-first")])
    write_findings(tmp_path, [_v(Severity.BLOCK, "R-second")])
    lines = (tmp_path / "STUCK_FAILURES.jsonl").read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2


def test_jsonl_not_created_when_no_matching_severity(tmp_path: Path):
    write_findings(tmp_path, [_v(Severity.INFO, "R-info")])
    assert not (tmp_path / "STUCK_FAILURES.jsonl").exists()
    assert not (tmp_path / "review-findings.jsonl").exists()
