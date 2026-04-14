import json
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "path_not_exist.py"
)


def _write_manifest(pi_root: Path, projects: list) -> None:
    (pi_root / "agent-records").mkdir(parents=True, exist_ok=True)
    manifest = {"overview": {"projectCount": len(projects)}, "projects": projects}
    (pi_root / "agent-records" / "restart-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )


def test_path_not_exist_fires_on_missing_path(tmp_path: Path):
    pi = tmp_path / "ProjectIndex"
    _write_manifest(pi, [{"name": "ghost", "path": str(tmp_path / "not-there")}])
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "P0-path-not-exist"
    assert verdicts[0].severity == Severity.BLOCK
    assert "ghost" in verdicts[0].detail


def test_path_not_exist_silent_on_all_paths_present(tmp_path: Path):
    pi = tmp_path / "ProjectIndex"
    real = tmp_path / "real_project"
    real.mkdir(parents=True)
    _write_manifest(pi, [{"name": "real", "path": str(real)}])
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    assert rule.check(ctx) == []


def test_path_not_exist_inactive_in_repo_scope(tmp_path: Path):
    pi = tmp_path / "ProjectIndex"
    _write_manifest(pi, [{"name": "ghost", "path": str(tmp_path / "nope")}])
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_path_not_exist_missing_manifest_blocks(tmp_path: Path):
    pi = tmp_path / "ProjectIndex"
    pi.mkdir()
    (pi / "agent-records").mkdir()
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.BLOCK
    assert "manifest" in verdicts[0].detail.lower()
