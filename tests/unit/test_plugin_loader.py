from pathlib import Path
import textwrap
import pytest

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import (
    load_plugin_rule,
    PluginRuleLoadError,
)


PLUGIN_VALID = textwrap.dedent("""
    from datetime import datetime, timezone
    from sentinel.core import Severity, Verdict

    ID = 'TEST-plugin'
    SEVERITY = Severity.WARN
    SOURCE = 'test.md'
    SCOPE = 'repo'

    def check(ctx):
        return [
            Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(ctx.repo_root),
                file=None,
                line=None,
                detail='hit',
                fix_hint='fix it',
                source=SOURCE,
                timestamp=datetime.now(timezone.utc),
            )
        ]
""")


def test_load_plugin_rule_returns_wrapper(tmp_path: Path):
    plugin_file = tmp_path / "plugin.py"
    plugin_file.write_text(PLUGIN_VALID, encoding="utf-8")
    rule = load_plugin_rule(plugin_file)
    assert rule.id == "TEST-plugin"
    assert rule.severity == Severity.WARN
    assert rule.scope == "repo"


def test_load_plugin_rule_missing_id_raises(tmp_path: Path):
    plugin_file = tmp_path / "plugin.py"
    plugin_file.write_text(
        PLUGIN_VALID.replace("ID = 'TEST-plugin'", ""), encoding="utf-8"
    )
    with pytest.raises(PluginRuleLoadError, match="missing required attribute: ID"):
        load_plugin_rule(plugin_file)


def test_load_plugin_rule_missing_check_raises(tmp_path: Path):
    plugin_file = tmp_path / "plugin.py"
    src = PLUGIN_VALID.replace("def check", "def _disabled_check")
    plugin_file.write_text(src, encoding="utf-8")
    with pytest.raises(PluginRuleLoadError, match="missing required attribute: check"):
        load_plugin_rule(plugin_file)


def test_plugin_rule_check_invokes_wrapped_function(tmp_path: Path):
    plugin_file = tmp_path / "plugin.py"
    plugin_file.write_text(PLUGIN_VALID, encoding="utf-8")
    rule = load_plugin_rule(plugin_file)

    repo = tmp_path / "repo"
    repo.mkdir()
    verdicts = rule.check(RepoContext(repo_root=repo, mode=ScanMode.REPO))
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "TEST-plugin"


def test_plugin_rule_check_catches_exceptions_as_block(tmp_path: Path):
    src = PLUGIN_VALID.replace(
        "return [", "raise RuntimeError('boom')  # noqa\n    return ["
    )
    plugin_file = tmp_path / "plugin.py"
    plugin_file.write_text(src, encoding="utf-8")
    rule = load_plugin_rule(plugin_file)
    repo = tmp_path / "repo"
    repo.mkdir()
    verdicts = rule.check(RepoContext(repo_root=repo, mode=ScanMode.REPO))
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.BLOCK
    assert "RuntimeError" in verdicts[0].detail
