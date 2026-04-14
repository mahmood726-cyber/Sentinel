from pathlib import Path
import pytest
from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.yaml_loader import load_yaml_rule, YamlRuleLoadError


YAML_VALID = """
id: TEST-pattern-match
severity: BLOCK
scope: repo
description: Test rule
pattern: 'FORBIDDEN_TOKEN'
files: ['**/*.txt']
exclude: ['ignore/**']
fix_hint: Remove the token.
source: test.md#forbidden
"""


def test_load_yaml_rule_parses_all_fields(tmp_path: Path):
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(YAML_VALID, encoding="utf-8")
    rule = load_yaml_rule(rule_file)
    assert rule.id == "TEST-pattern-match"
    assert rule.severity == Severity.BLOCK
    assert rule.scope == "repo"
    assert rule.pattern == "FORBIDDEN_TOKEN"
    assert rule.files == ["**/*.txt"]
    assert rule.exclude == ["ignore/**"]


def test_load_yaml_rule_missing_required_field_raises(tmp_path: Path):
    rule_file = tmp_path / "bad.yaml"
    rule_file.write_text("id: incomplete\nseverity: BLOCK\n", encoding="utf-8")
    with pytest.raises(YamlRuleLoadError, match="missing required field"):
        load_yaml_rule(rule_file)


def test_load_yaml_rule_unknown_severity_raises(tmp_path: Path):
    rule_file = tmp_path / "bad.yaml"
    bad = YAML_VALID.replace("severity: BLOCK", "severity: CRITICAL")
    rule_file.write_text(bad, encoding="utf-8")
    with pytest.raises(YamlRuleLoadError, match="unknown severity"):
        load_yaml_rule(rule_file)


def test_yaml_rule_check_finds_pattern(tmp_path: Path):
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(YAML_VALID, encoding="utf-8")
    rule = load_yaml_rule(rule_file)

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "hit.txt").write_text("some FORBIDDEN_TOKEN here\n", encoding="utf-8")
    (repo / "miss.txt").write_text("clean content\n", encoding="utf-8")

    ctx = RepoContext(repo_root=repo, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "TEST-pattern-match"
    assert verdicts[0].file == "hit.txt"
    assert verdicts[0].line == 1


def test_yaml_rule_check_respects_exclude(tmp_path: Path):
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(YAML_VALID, encoding="utf-8")
    rule = load_yaml_rule(rule_file)

    repo = tmp_path / "repo"
    (repo / "ignore").mkdir(parents=True)
    (repo / "ignore" / "skip.txt").write_text("FORBIDDEN_TOKEN\n", encoding="utf-8")

    ctx = RepoContext(repo_root=repo, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_yaml_rule_scope_defaults_to_repo(tmp_path: Path):
    rule_file = tmp_path / "rule.yaml"
    no_scope = YAML_VALID.replace("scope: repo\n", "")
    rule_file.write_text(no_scope, encoding="utf-8")
    rule = load_yaml_rule(rule_file)
    assert rule.scope == "repo"
