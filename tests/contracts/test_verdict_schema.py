"""Contract: every verdict produced by every shipped rule matches the schema."""
from datetime import datetime
from pathlib import Path
import pytest
from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.registry import Registry

RULES_ROOT = Path(__file__).parent.parent.parent / "sentinel" / "rules"


REQUIRED_KEYS = {
    "rule_id", "severity", "repo", "file", "line",
    "detail", "fix_hint", "source", "timestamp",
}


@pytest.mark.contract
def test_verdict_schema_from_registry(tmp_path: Path):
    reg = Registry.from_dir(RULES_ROOT)
    pi = tmp_path / "ProjectIndex"
    pi.mkdir()
    (pi / "agent-records").mkdir()
    (pi / "agent-records" / "restart-manifest.json").write_text(
        '{"overview":{"projectCount":1},"projects":[{"name":"x","path":"C:/not/here"}]}',
        encoding="utf-8",
    )
    (pi / "reconcile_counts.py").write_text("import sys; sys.exit(1)", encoding="utf-8")

    repo_ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    port_ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )

    all_verdicts = []
    for rule in reg.all_rules():
        all_verdicts.extend(rule.check(repo_ctx))
        all_verdicts.extend(rule.check(port_ctx))

    assert all_verdicts, "at least one rule should produce a verdict in this setup"
    for v in all_verdicts:
        d = v.to_dict()
        assert set(d.keys()) == REQUIRED_KEYS, f"missing keys: {REQUIRED_KEYS - set(d.keys())}"
        assert d["severity"] in ("BLOCK", "WARN", "INFO")
        datetime.fromisoformat(d["timestamp"])
