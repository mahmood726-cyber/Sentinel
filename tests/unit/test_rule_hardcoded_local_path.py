from pathlib import Path
from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.yaml_loader import load_yaml_rule


RULE_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "yaml" / "P0-hardcoded-local-path.yaml"
)


def test_hardcoded_local_path_fires_on_bad_fixture(fixtures_dir: Path):
    rule = load_yaml_rule(RULE_PATH)
    bad = fixtures_dir / "repos" / "hardcoded_path_BAD"
    verdicts = rule.check(RepoContext(repo_root=bad, mode=ScanMode.REPO))
    assert len(verdicts) >= 1
    assert all(v.severity == Severity.BLOCK for v in verdicts)


def test_hardcoded_local_path_silent_on_good_fixture(fixtures_dir: Path):
    rule = load_yaml_rule(RULE_PATH)
    good = fixtures_dir / "repos" / "hardcoded_path_GOOD"
    verdicts = rule.check(RepoContext(repo_root=good, mode=ScanMode.REPO))
    assert verdicts == []


def test_hardcoded_local_path_excludes_nested_test_dirs(tmp_path: Path):
    """Workbench-style layout: <app>/tests/*.py containing rules-doc
    references like C:/Users/user/.claude/... in a docstring is a
    pointer, not shipping code. Nested test dirs must be excluded."""
    app_tests = tmp_path / "prisma-flow" / "tests"
    app_tests.mkdir(parents=True)
    (app_tests / "test_prisma.py").write_text(
        '"""Test: no external CDN at runtime\n'
        '  (offline-safe per C:/Users/user/.claude/rules/html-apps.md).\n'
        '"""\n',
        encoding="utf-8",
    )
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert verdicts == [], f"nested test docstring should be excluded: {[v.file for v in verdicts]}"
