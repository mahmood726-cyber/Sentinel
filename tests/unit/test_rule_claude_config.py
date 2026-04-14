from pathlib import Path
from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.yaml_loader import load_yaml_rule


RULE_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "yaml" / "P0-claude-config-committed.yaml"
)


def test_claude_config_fires_on_bad_fixture(fixtures_dir: Path):
    rule = load_yaml_rule(RULE_PATH)
    bad = fixtures_dir / "repos" / "claude_config_BAD"
    verdicts = rule.check(RepoContext(repo_root=bad, mode=ScanMode.REPO))
    assert len(verdicts) >= 1
    assert all(v.severity == Severity.BLOCK for v in verdicts)


def test_claude_config_silent_on_good_fixture(fixtures_dir: Path):
    rule = load_yaml_rule(RULE_PATH)
    good = fixtures_dir / "repos" / "claude_config_GOOD"
    verdicts = rule.check(RepoContext(repo_root=good, mode=ScanMode.REPO))
    assert verdicts == []
