"""Unit tests for SARIF 2.1.0 emitter (sentinel.io.sarif).

SARIF (Static Analysis Results Interchange Format) is the canonical format
for GitHub code-scanning, GitLab SAST, Azure DevOps, and most IDEs. By
emitting SARIF, Sentinel findings can land in the GitHub "Security" tab
instead of needing the bespoke `sentinel-findings.md` dashboard.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Coverage targets:
  - empty verdict list → valid SARIF with no results
  - BLOCK/WARN/INFO map to error/warning/note
  - rule_id, file, line preserved
  - schema + version fields valid
  - all rules referenced in results appear in tool.driver.rules
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinel.core import Severity, Verdict
from sentinel.io.sarif import verdicts_to_sarif, SARIF_SCHEMA, SARIF_VERSION


def _v(rule_id: str, sev: Severity, file: str | None = None,
       line: int | None = None, detail: str = "test detail") -> Verdict:
    return Verdict(
        rule_id=rule_id, severity=sev, repo="test-repo",
        file=file, line=line, detail=detail,
        fix_hint="test fix", source="test source",
        timestamp=datetime(2026, 4, 28, 12, 0, 0, tzinfo=timezone.utc),
    )


def test_empty_verdicts_produces_valid_sarif():
    sarif = verdicts_to_sarif([])
    assert sarif["$schema"] == SARIF_SCHEMA
    assert sarif["version"] == SARIF_VERSION
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "Sentinel"


def test_block_maps_to_error_level():
    sarif = verdicts_to_sarif([_v("P0-test", Severity.BLOCK)])
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["level"] == "error"


def test_warn_maps_to_warning_level():
    sarif = verdicts_to_sarif([_v("P1-test", Severity.WARN)])
    assert sarif["runs"][0]["results"][0]["level"] == "warning"


def test_info_maps_to_note_level():
    sarif = verdicts_to_sarif([_v("P2-test", Severity.INFO)])
    assert sarif["runs"][0]["results"][0]["level"] == "note"


def test_rule_id_and_message_preserved():
    sarif = verdicts_to_sarif(
        [_v("P0-placeholder-hmac", Severity.BLOCK, detail="found SIG_RSA_x")]
    )
    r = sarif["runs"][0]["results"][0]
    assert r["ruleId"] == "P0-placeholder-hmac"
    assert r["message"]["text"] == "found SIG_RSA_x"


def test_file_and_line_become_physical_location():
    sarif = verdicts_to_sarif(
        [_v("P0-test", Severity.BLOCK, file="src/foo.py", line=42)]
    )
    r = sarif["runs"][0]["results"][0]
    loc = r["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/foo.py"
    assert loc["region"]["startLine"] == 42


def test_repo_wide_finding_omits_locations_array():
    """SARIF spec: results without a physical location should still be valid;
    we omit the `locations` array (or include it empty) per spec §3.27.12."""
    sarif = verdicts_to_sarif([_v("P0-test", Severity.BLOCK, file=None, line=None)])
    r = sarif["runs"][0]["results"][0]
    # Either no `locations` key or empty list — both are valid SARIF
    assert "locations" not in r or r["locations"] == []


def test_unique_rule_ids_appear_in_tool_driver_rules():
    """SARIF requires every ruleId in results to be defined in tool.driver.rules
    so SARIF-consuming tools can show the rule's full description."""
    verdicts = [
        _v("P0-a", Severity.BLOCK, detail="d1"),
        _v("P0-a", Severity.BLOCK, detail="d2"),  # duplicate rule_id
        _v("P1-b", Severity.WARN, detail="d3"),
    ]
    sarif = verdicts_to_sarif(verdicts)
    rule_ids_in_defs = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    rule_ids_in_results = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert rule_ids_in_results.issubset(rule_ids_in_defs)
    # Also: rules array should have exactly the unique set, no duplicates
    assert len(rule_ids_in_defs) == len({"P0-a", "P1-b"})


def test_sarif_serializes_to_json():
    """Round-trip through json.dumps must succeed (no datetime, no non-JSON types)."""
    sarif = verdicts_to_sarif([_v("P0-test", Severity.BLOCK, file="x.py", line=1)])
    s = json.dumps(sarif)
    parsed = json.loads(s)
    assert parsed["version"] == SARIF_VERSION


def test_scan_cli_emits_sarif_when_flag_passed(tmp_path: Path):
    """End-to-end: `sentinel scan --repo X --sarif` writes a SARIF file."""
    import subprocess
    import sys
    SENTINEL_ROOT = Path(__file__).parent.parent.parent
    bad = tmp_path / "bad"
    bad.mkdir()
    subprocess.run(["git", "init", "-q", str(bad)], check=True)
    (bad / "cert.json").write_text(
        '{"sig":"SIG_RSA_SHA256_x"}', encoding="utf-8"
    )
    res = subprocess.run(
        [sys.executable, "-m", "sentinel", "scan", "--repo", str(bad), "--sarif"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(SENTINEL_ROOT),
    )
    assert res.returncode == 1, f"expected BLOCK exit, stderr: {res.stderr}"
    sarif_path = bad / "sentinel-findings.sarif"
    assert sarif_path.exists(), \
        f"sarif output missing; stderr: {res.stderr}"
    with sarif_path.open("r", encoding="utf-8") as f:
        sarif = json.load(f)
    assert sarif["version"] == SARIF_VERSION
    assert any(
        r["ruleId"] == "P0-placeholder-hmac"
        for r in sarif["runs"][0]["results"]
    )
