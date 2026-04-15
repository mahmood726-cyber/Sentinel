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
    warn = (tmp_path / "sentinel-findings.md").read_text(encoding="utf-8")
    assert "R-block" in stuck
    assert "R-warn" not in stuck
    assert "R-warn" in warn


def test_info_only_creates_no_files(tmp_path: Path):
    write_findings(tmp_path, [_v(Severity.INFO, "R-info")])
    assert not (tmp_path / "STUCK_FAILURES.md").exists()
    assert not (tmp_path / "sentinel-findings.md").exists()


def test_empty_verdicts_creates_no_files(tmp_path: Path):
    write_findings(tmp_path, [])
    assert not (tmp_path / "STUCK_FAILURES.md").exists()
    assert not (tmp_path / "sentinel-findings.md").exists()


def test_appends_to_existing_review_findings(tmp_path: Path):
    (tmp_path / "sentinel-findings.md").write_text("# existing\n\n", encoding="utf-8")
    write_findings(tmp_path, [_v(Severity.WARN, "R-warn")])
    content = (tmp_path / "sentinel-findings.md").read_text(encoding="utf-8")
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
    lines = (tmp_path / "sentinel-findings.jsonl").read_text(encoding="utf-8").strip().split("\n")
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
    assert not (tmp_path / "sentinel-findings.jsonl").exists()


def test_md_and_jsonl_have_matching_rule_ids(tmp_path: Path):
    """P2-6: For every verdict written to MD, an equivalent record must
    appear in JSONL. Downstream aggregators prefer JSONL; silent
    desynchronization between the two would corrupt reporting."""
    import json
    verdicts = [
        _v(Severity.BLOCK, "R-b1"),
        _v(Severity.BLOCK, "R-b2"),
        _v(Severity.WARN, "R-w1"),
    ]
    write_findings(tmp_path, verdicts)

    md_block = (tmp_path / "STUCK_FAILURES.md").read_text(encoding="utf-8")
    md_warn = (tmp_path / "sentinel-findings.md").read_text(encoding="utf-8")
    jsonl_block = (tmp_path / "STUCK_FAILURES.jsonl").read_text(encoding="utf-8").strip().split("\n")
    jsonl_warn = (tmp_path / "sentinel-findings.jsonl").read_text(encoding="utf-8").strip().split("\n")

    md_block_ids = {line.split("]")[1].strip() for line in md_block.splitlines() if line.startswith("## [BLOCK]")}
    md_warn_ids = {line.split("]")[1].strip() for line in md_warn.splitlines() if line.startswith("## [WARN]")}
    jsonl_block_ids = {json.loads(line)["rule_id"] for line in jsonl_block}
    jsonl_warn_ids = {json.loads(line)["rule_id"] for line in jsonl_warn}

    assert md_block_ids == jsonl_block_ids == {"R-b1", "R-b2"}
    assert md_warn_ids == jsonl_warn_ids == {"R-w1"}


def test_jsonl_distinct_timestamps_survive_append(tmp_path: Path):
    """P2-8: Two appends with different timestamps must preserve both
    timestamps in JSONL (no silent clobber)."""
    import json
    v1 = Verdict(rule_id="R-1", severity=Severity.BLOCK, repo="C:/repo",
                 file="a.py", line=1, detail="d", fix_hint="fh", source="s",
                 timestamp=datetime(2026, 4, 14, 10, 0, 0, tzinfo=timezone.utc))
    v2 = Verdict(rule_id="R-2", severity=Severity.BLOCK, repo="C:/repo",
                 file="b.py", line=2, detail="d", fix_hint="fh", source="s",
                 timestamp=datetime(2026, 4, 15, 12, 30, 0, tzinfo=timezone.utc))
    write_findings(tmp_path, [v1])
    write_findings(tmp_path, [v2])
    lines = (tmp_path / "STUCK_FAILURES.jsonl").read_text(encoding="utf-8").strip().split("\n")
    stamps = [json.loads(line)["timestamp"] for line in lines]
    assert stamps == [
        "2026-04-14T10:00:00+00:00",
        "2026-04-15T12:30:00+00:00",
    ]
