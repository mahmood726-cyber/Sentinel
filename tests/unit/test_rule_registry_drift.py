import textwrap
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "registry_drift.py"
)

STUB_OK = textwrap.dedent("""
    import sys
    print("ok")
    sys.exit(0)
""")

STUB_FAIL = textwrap.dedent("""
    import sys
    sys.stderr.write("drift detected: 517 vs 472\\n")
    sys.exit(1)
""")


def _setup_pi(tmp_path: Path, stub_src: str) -> Path:
    pi = tmp_path / "ProjectIndex"
    pi.mkdir()
    (pi / "reconcile_counts.py").write_text(stub_src, encoding="utf-8")
    return pi


def test_registry_drift_silent_when_reconcile_exits_zero(tmp_path: Path):
    pi = _setup_pi(tmp_path, STUB_OK)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    assert rule.check(ctx) == []


def test_registry_drift_blocks_when_reconcile_exits_nonzero(tmp_path: Path):
    pi = _setup_pi(tmp_path, STUB_FAIL)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "P0-registry-drift"
    assert verdicts[0].severity == Severity.BLOCK
    assert "517" in verdicts[0].detail or "472" in verdicts[0].detail


def test_registry_drift_missing_script_blocks(tmp_path: Path):
    pi = tmp_path / "ProjectIndex"
    pi.mkdir()  # no reconcile_counts.py
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.BLOCK
    assert "reconcile_counts.py not found" in verdicts[0].detail


def test_registry_drift_inactive_in_repo_scope(tmp_path: Path):
    pi = _setup_pi(tmp_path, STUB_FAIL)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []
