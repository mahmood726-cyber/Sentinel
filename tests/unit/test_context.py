from pathlib import Path
from sentinel.core.context import RepoContext, ScanMode


def test_repo_context_repo_mode(tmp_path: Path):
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert ctx.repo_root == tmp_path
    assert ctx.mode == ScanMode.REPO
    assert ctx.is_repo_scan()
    assert not ctx.is_portfolio_scan()


def test_repo_context_portfolio_mode(tmp_path: Path):
    ctx = RepoContext(
        repo_root=tmp_path,
        mode=ScanMode.PORTFOLIO,
        project_index_root=tmp_path / "ProjectIndex",
    )
    assert ctx.is_portfolio_scan()
    assert ctx.project_index_root == tmp_path / "ProjectIndex"


def test_repo_context_portfolio_requires_project_index_root(tmp_path: Path):
    import pytest
    with pytest.raises(ValueError, match="project_index_root required"):
        RepoContext(repo_root=tmp_path, mode=ScanMode.PORTFOLIO)
