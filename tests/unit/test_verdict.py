from datetime import datetime, timezone
from sentinel.core.verdict import Verdict
from sentinel.core.severity import Severity


def test_verdict_to_dict_round_trips_all_fields():
    ts = datetime(2026, 4, 14, 10, 23, 0, tzinfo=timezone.utc)
    v = Verdict(
        rule_id="P0-placeholder-hmac",
        severity=Severity.BLOCK,
        repo="C:/Projects/shifaa",
        file="shifaa/bundles/cert_v1.json",
        line=42,
        detail="placeholder signature shipped",
        fix_hint="replace with env TRUTHCERT_HMAC_KEY",
        source="lessons.md#cryptography-signing",
        timestamp=ts,
    )
    d = v.to_dict()
    assert d["rule_id"] == "P0-placeholder-hmac"
    assert d["severity"] == "BLOCK"
    assert d["line"] == 42
    assert d["timestamp"] == "2026-04-14T10:23:00+00:00"


def test_verdict_accepts_none_line_and_file_for_repo_wide_findings():
    v = Verdict(
        rule_id="P0-registry-drift",
        severity=Severity.BLOCK,
        repo="C:/ProjectIndex",
        file=None,
        line=None,
        detail="manifest missing",
        fix_hint="restore manifest",
        source="workflow.md",
        timestamp=datetime.now(timezone.utc),
    )
    d = v.to_dict()
    assert d["file"] is None
    assert d["line"] is None
