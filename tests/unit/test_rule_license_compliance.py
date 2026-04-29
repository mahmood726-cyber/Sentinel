"""Unit tests for P1-license-noncompliance Sentinel rule.

The rule checks whether a repo's declared deps (requirements.txt /
pyproject.toml) include packages with copyleft licenses (GPL/AGPL),
which would conflict with MIT publication.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.rules.plugins import license_compliance as lc


def _ctx(path: Path) -> RepoContext:
    return RepoContext(repo_root=path, mode=ScanMode.REPO)


# ── _normalize_pkg ────────────────────────────────────────────────────


def test_normalize_pkg_handles_pep503():
    assert lc._normalize_pkg("Some_Package") == "some-package"
    assert lc._normalize_pkg("requests") == "requests"
    assert lc._normalize_pkg("Pip.Tools") == "pip-tools"


# ── _is_forbidden ─────────────────────────────────────────────────────


def test_forbidden_gpl_variants():
    assert lc._is_forbidden("GPL-3.0")
    assert lc._is_forbidden("GPL-3.0-only")
    assert lc._is_forbidden("GPL-3.0-or-later")
    assert lc._is_forbidden("GPL-2.0")
    assert lc._is_forbidden("GNU General Public License v3 (GPLv3)")
    assert lc._is_forbidden("AGPL-3.0")
    assert lc._is_forbidden("GNU Affero General Public License v3.0")


def test_forbidden_does_not_match_lgpl():
    """LGPL is dynamic-linking-compatible with MIT; we don't block it."""
    assert not lc._is_forbidden("LGPL-3.0")
    assert not lc._is_forbidden("GNU Lesser General Public License v3")


def test_forbidden_does_not_match_permissive():
    assert not lc._is_forbidden("MIT")
    assert not lc._is_forbidden("BSD-3-Clause")
    assert not lc._is_forbidden("Apache-2.0")
    assert not lc._is_forbidden("ISC")
    assert not lc._is_forbidden("Python-2.0")
    assert not lc._is_forbidden("MPL-2.0")


def test_forbidden_does_not_match_unknown():
    """UNKNOWN license should not be flagged (it's an indeterminate signal,
    not a positive identification of GPL)."""
    assert not lc._is_forbidden("UNKNOWN")
    assert not lc._is_forbidden("")


# ── _parse_requirements ───────────────────────────────────────────────


def test_parse_requirements_basic(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text(
        "requests>=2.0\n"
        "pandas==1.5.3\n"
        "numpy\n",
        encoding="utf-8",
    )
    pkgs = lc._parse_requirements(tmp_path / "requirements.txt")
    assert pkgs == {"requests", "pandas", "numpy"}


def test_parse_requirements_skips_comments_and_directives(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text(
        "# a comment\n"
        "-r other.txt\n"
        "-e git+https://example.com/repo.git#egg=mypkg\n"
        "https://example.com/wheel.whl\n"
        "\n"
        "requests\n",
        encoding="utf-8",
    )
    pkgs = lc._parse_requirements(tmp_path / "requirements.txt")
    assert pkgs == {"requests"}


def test_parse_requirements_handles_extras(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text(
        "celery[redis]>=5.0\n", encoding="utf-8",
    )
    pkgs = lc._parse_requirements(tmp_path / "requirements.txt")
    assert pkgs == {"celery"}


# ── _parse_pyproject ──────────────────────────────────────────────────


def test_parse_pyproject_pep621(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "demo"\n'
        'dependencies = [\n'
        '    "requests >=2.0",\n'
        '    "pandas",\n'
        ']\n',
        encoding="utf-8",
    )
    pkgs = lc._parse_pyproject(tmp_path / "pyproject.toml")
    assert pkgs == {"requests", "pandas"}


def test_parse_pyproject_poetry_excludes_python(tmp_path: Path):
    """Poetry's `python = "^3.10"` marker must NOT be treated as a dep."""
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\n'
        'python = "^3.10"\n'
        'requests = "^2.0"\n'
        'pandas = "^1.5"\n',
        encoding="utf-8",
    )
    pkgs = lc._parse_pyproject(tmp_path / "pyproject.toml")
    assert pkgs == {"requests", "pandas"}
    assert "python" not in pkgs


# ── check() integration ──────────────────────────────────────────────


def _git_init(path: Path):
    import subprocess
    subprocess.run(["git", "init", "-q", str(path)], check=True)


def test_check_no_deps_no_findings(tmp_path: Path):
    repo = tmp_path / "demo"
    repo.mkdir()
    _git_init(repo)
    verdicts = lc.check(_ctx(repo))
    assert verdicts == []


def test_check_skips_when_pip_licenses_unavailable(tmp_path: Path):
    repo = tmp_path / "demo"
    repo.mkdir()
    _git_init(repo)
    (repo / "requirements.txt").write_text("gpl-pkg\n", encoding="utf-8")
    with patch.object(lc, "_pip_licenses_snapshot", return_value=None):
        verdicts = lc.check(_ctx(repo))
    # SKIP semantics: no verdicts, no error. Caller gets clean run.
    assert verdicts == []


def test_check_flags_gpl_dep(tmp_path: Path):
    repo = tmp_path / "demo"
    repo.mkdir()
    _git_init(repo)
    (repo / "requirements.txt").write_text("evil-gpl-pkg\n", encoding="utf-8")
    fake_snapshot = {
        "evil-gpl-pkg": "GPL-3.0-or-later",
        "requests": "Apache-2.0",
    }
    with patch.object(lc, "_pip_licenses_snapshot", return_value=fake_snapshot):
        verdicts = lc.check(_ctx(repo))
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "P1-license-noncompliance"
    assert verdicts[0].severity == Severity.WARN
    assert "evil-gpl-pkg" in verdicts[0].detail
    assert "GPL-3.0" in verdicts[0].detail


def test_check_does_not_flag_permissive_deps(tmp_path: Path):
    repo = tmp_path / "demo"
    repo.mkdir()
    _git_init(repo)
    (repo / "requirements.txt").write_text(
        "requests\nnumpy\npandas\n", encoding="utf-8",
    )
    fake_snapshot = {
        "requests": "Apache-2.0",
        "numpy": "BSD-3-Clause",
        "pandas": "BSD-3-Clause",
    }
    with patch.object(lc, "_pip_licenses_snapshot", return_value=fake_snapshot):
        verdicts = lc.check(_ctx(repo))
    assert verdicts == []


def test_check_skips_dep_not_in_snapshot(tmp_path: Path):
    """Declared but not installed → can't determine license → skip silently
    (don't false-flag)."""
    repo = tmp_path / "demo"
    repo.mkdir()
    _git_init(repo)
    (repo / "requirements.txt").write_text("missing-pkg\n", encoding="utf-8")
    with patch.object(lc, "_pip_licenses_snapshot", return_value={}):
        verdicts = lc.check(_ctx(repo))
    assert verdicts == []


def test_check_handles_pyproject_only(tmp_path: Path):
    repo = tmp_path / "demo"
    repo.mkdir()
    _git_init(repo)
    (repo / "pyproject.toml").write_text(
        '[project]\n'
        'name = "demo"\n'
        'dependencies = [ "agpl-pkg >=1.0" ]\n',
        encoding="utf-8",
    )
    fake_snapshot = {"agpl-pkg": "GNU Affero General Public License v3.0"}
    with patch.object(lc, "_pip_licenses_snapshot", return_value=fake_snapshot):
        verdicts = lc.check(_ctx(repo))
    assert len(verdicts) == 1
    assert "agpl-pkg" in verdicts[0].detail


def test_check_severity_is_warn_not_block():
    """Reason-test: WARN is a deliberate choice (some repos legitimately
    use copyleft). Promotion to BLOCK requires the same evidence as
    leaked_secret promotion did — a portfolio sweep with zero false
    positives."""
    assert lc.SEVERITY == Severity.WARN
