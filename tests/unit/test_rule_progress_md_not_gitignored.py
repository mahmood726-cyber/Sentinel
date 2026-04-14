# tests/unit/test_rule_progress_md_not_gitignored.py
import subprocess
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "progress_md_not_gitignored.py"
)


def _git_init(path: Path) -> None:
    subprocess.run(["git", "init", "-b", "main"], cwd=str(path),
                   capture_output=True, check=True)
    # identity is required for commits
    subprocess.run(["git", "config", "user.email", "x@x"], cwd=str(path), check=True)
    subprocess.run(["git", "config", "user.name", "x"], cwd=str(path), check=True)


def test_progress_md_info_when_tracked_and_not_gitignored(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git_init(repo)
    (repo / "PROGRESS.md").write_text("# progress\n", encoding="utf-8")
    subprocess.run(["git", "add", "PROGRESS.md"], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo), check=True,
                   capture_output=True)
    rule = load_plugin_rule(PLUGIN_PATH)
    verdicts = rule.check(RepoContext(repo_root=repo, mode=ScanMode.REPO))
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.INFO


def test_progress_md_silent_when_gitignored(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git_init(repo)
    (repo / ".gitignore").write_text("PROGRESS.md\n", encoding="utf-8")
    (repo / "PROGRESS.md").write_text("# progress\n", encoding="utf-8")
    subprocess.run(["git", "add", ".gitignore"], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "gi"], cwd=str(repo), check=True,
                   capture_output=True)
    rule = load_plugin_rule(PLUGIN_PATH)
    verdicts = rule.check(RepoContext(repo_root=repo, mode=ScanMode.REPO))
    assert verdicts == []


def test_progress_md_silent_when_no_progress_md(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git_init(repo)
    rule = load_plugin_rule(PLUGIN_PATH)
    assert rule.check(RepoContext(repo_root=repo, mode=ScanMode.REPO)) == []
