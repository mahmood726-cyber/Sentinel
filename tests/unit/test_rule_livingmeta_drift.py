import textwrap
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "livingmeta_drift.py"
)

STUB_CLEAN = textwrap.dedent("""
    import sys
    print("CLAIM-DRIFT SUMMARY: 40 clean / 0 drift / 0 skipped")
    sys.exit(0)
""")

STUB_DRIFT = textwrap.dedent("""
    import sys
    print("CLAIM-DRIFT SUMMARY: 39 clean / 1 drift / 0 skipped")
    print("- **Sotatercept_PAH**: missing NCT: ['NCT04576988']")
    sys.exit(2)
""")

STUB_CRASH = textwrap.dedent("""
    import sys
    sys.stderr.write("Traceback ...\\nRuntimeError: boom\\n")
    sys.exit(1)
""")


def _setup_pi(tmp_path: Path, stub_src: str) -> Path:
    pi = tmp_path / "ProjectIndex"
    pi.mkdir()
    (pi / "audit_livingmeta_claims.py").write_text(stub_src, encoding="utf-8")
    return pi


def test_livingmeta_drift_silent_when_audit_exits_zero(tmp_path: Path):
    pi = _setup_pi(tmp_path, STUB_CLEAN)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    assert rule.check(ctx) == []


def test_livingmeta_drift_blocks_when_audit_exits_two(tmp_path: Path):
    pi = _setup_pi(tmp_path, STUB_DRIFT)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.rule_id == "P0-livingmeta-drift"
    assert v.severity == Severity.BLOCK
    assert "drift" in v.detail.lower()
    assert "Sotatercept_PAH" in v.detail or "1 drift" in v.detail


def test_livingmeta_drift_blocks_on_script_crash(tmp_path: Path):
    pi = _setup_pi(tmp_path, STUB_CRASH)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.severity == Severity.BLOCK
    assert "exit 1" in v.detail or "exited 1" in v.detail
    assert "boom" in v.detail or "RuntimeError" in v.detail


def test_livingmeta_drift_missing_script_blocks(tmp_path: Path):
    pi = tmp_path / "ProjectIndex"
    pi.mkdir()
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.BLOCK
    assert "audit_livingmeta_claims.py not found" in verdicts[0].detail


def test_livingmeta_drift_inactive_in_repo_scope(tmp_path: Path):
    pi = _setup_pi(tmp_path, STUB_DRIFT)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []
