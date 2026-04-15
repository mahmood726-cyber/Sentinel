"""Tests for P2-agent-config-version-drift plugin rule."""
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.rules.plugins.agent_config_version_drift import (
    _authoritative_version,
    check,
)


def _make_project(project_root: Path, version: str, source: str = "pyproject") -> None:
    """Create a minimal project with the specified version source."""
    project_root.mkdir(parents=True, exist_ok=True)
    if source == "pyproject":
        (project_root / "pyproject.toml").write_text(
            f'[project]\nname = "x"\nversion = "{version}"\n',
            encoding="utf-8",
        )
    elif source == "init":
        pkg = project_root / "x_pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text(
            f'__version__ = "{version}"\n', encoding="utf-8",
        )
    elif source == "package_json":
        (project_root / "package.json").write_text(
            f'{{"name": "x", "version": "{version}"}}\n',
            encoding="utf-8",
        )


def test_authoritative_version_reads_pyproject(tmp_path: Path):
    _make_project(tmp_path, "1.2.3", "pyproject")
    assert _authoritative_version(tmp_path) == "1.2.3"


def test_authoritative_version_reads_init_py(tmp_path: Path):
    _make_project(tmp_path, "2.0.0", "init")
    assert _authoritative_version(tmp_path) == "2.0.0"


def test_authoritative_version_reads_package_json(tmp_path: Path):
    _make_project(tmp_path, "3.1.4", "package_json")
    assert _authoritative_version(tmp_path) == "3.1.4"


def test_authoritative_version_pyproject_wins_over_init(tmp_path: Path):
    """When both pyproject.toml and __init__.py are present, pyproject
    is the packaging source of truth."""
    _make_project(tmp_path, "5.0.0", "pyproject")
    _make_project(tmp_path, "4.0.0", "init")
    assert _authoritative_version(tmp_path) == "5.0.0"


def test_authoritative_version_returns_none_when_no_source(tmp_path: Path):
    (tmp_path / "README.md").write_text("no version source here\n", encoding="utf-8")
    assert _authoritative_version(tmp_path) is None


def test_check_flags_version_mismatch(tmp_path: Path):
    """AGENTS.md claims v2.1.0; pyproject says v3.1.0 → WARN."""
    project = tmp_path / "myproj"
    _make_project(project, "3.1.0", "pyproject")
    (tmp_path / "AGENTS.md").write_text(
        f"# AGENTS\n\n"
        f"- **MyProj** (`{project.as_posix()}`, v2.1.0) is the thing.\n",
        encoding="utf-8",
    )
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    verdicts = check(ctx)
    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.severity == Severity.WARN
    assert v.file == "AGENTS.md"
    assert "v2.1.0" in v.detail
    assert "v3.1.0" in v.detail
    assert "MyProj" in v.detail


def test_check_silent_when_versions_match(tmp_path: Path):
    project = tmp_path / "myproj"
    _make_project(project, "3.1.0", "pyproject")
    (tmp_path / "AGENTS.md").write_text(
        f"- **MyProj** (`{project.as_posix()}`, v3.1.0) is the thing.\n",
        encoding="utf-8",
    )
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert check(ctx) == []


def test_check_silent_when_no_authoritative_source(tmp_path: Path):
    """Claim references a directory with no pyproject/package.json/init —
    can't verify, so skip silently (don't emit false positives)."""
    project = tmp_path / "bare-dir"
    project.mkdir()
    (tmp_path / "AGENTS.md").write_text(
        f"- **Bare** (`{project.as_posix()}`, v1.0.0) is the thing.\n",
        encoding="utf-8",
    )
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert check(ctx) == []


def test_check_silent_when_path_doesnt_exist(tmp_path: Path):
    """Claim references a path that doesn't resolve on disk. Not our
    business — a different rule (P0-path-not-exist) handles that."""
    (tmp_path / "AGENTS.md").write_text(
        "- **Ghost** (`C:/does/not/exist`, v1.0.0) is the thing.\n",
        encoding="utf-8",
    )
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert check(ctx) == []


def test_check_silent_when_no_version_in_claim(tmp_path: Path):
    """Claim has path but no version → nothing to validate, no verdict."""
    project = tmp_path / "myproj"
    _make_project(project, "3.1.0", "pyproject")
    (tmp_path / "AGENTS.md").write_text(
        f"- **MyProj** (`{project.as_posix()}`) is the thing.\n",
        encoding="utf-8",
    )
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert check(ctx) == []


def test_check_scans_multiple_config_files(tmp_path: Path):
    """Same drift recorded in both AGENTS.md and CLAUDE.md → two verdicts."""
    project = tmp_path / "myproj"
    _make_project(project, "3.1.0", "pyproject")
    stale_claim = f"- **MyProj** (`{project.as_posix()}`, v2.1.0) is the thing.\n"
    (tmp_path / "AGENTS.md").write_text(stale_claim, encoding="utf-8")
    (tmp_path / "CLAUDE.md").write_text(stale_claim, encoding="utf-8")
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    verdicts = check(ctx)
    assert len(verdicts) == 2
    assert {v.file for v in verdicts} == {"AGENTS.md", "CLAUDE.md"}


def test_check_runs_in_empty_repo(tmp_path: Path):
    """No config files present → no verdicts, no crash."""
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert check(ctx) == []
