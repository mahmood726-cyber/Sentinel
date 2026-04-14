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
