# sentinel:skip-file — synthetic regression strings include intentionally unsafe calls.
"""Whitespace-separated Python eval/exec calls must not evade the BLOCK rule.

Both a tracked risky call and matched valid-code controls are represented by
deterministic local files. No publications, credentials, or network access.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "unsafe_eval_exec.py"
)


def _check_source(tmp_path: Path, source: str):
    # Prove the reproducer is valid Python rather than a syntax-error fixture.
    compile(source, "<synthetic>", "exec")
    (tmp_path / "module.py").write_text(source, encoding="utf-8")
    rule = load_plugin_rule(PLUGIN)
    return rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))


@pytest.mark.parametrize("source", [
    "result = eval (user_input)\n",
    "exec \t(payload)\n",
])
def test_whitespace_before_paren_cannot_hide_dynamic_calls(
    tmp_path: Path, source: str
) -> None:
    verdicts = _check_source(tmp_path, source)
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "P0-unsafe-eval-exec"
    assert verdicts[0].severity == Severity.BLOCK
    assert verdicts[0].file == "module.py"
    assert verdicts[0].line == 1


@pytest.mark.parametrize("source", [
    'result = eval ("2 + 2")\n',
    'text = "eval (user_input)"\n',
    '# eval (user_input)\nresult = 1\n',
    'import ast\nresult = ast.literal_eval (value)\n',
    'result = evaluate (value)\n',
])
def test_whitespace_and_noncall_controls_stay_clean(
    tmp_path: Path, source: str
) -> None:
    assert _check_source(tmp_path, source) == []
