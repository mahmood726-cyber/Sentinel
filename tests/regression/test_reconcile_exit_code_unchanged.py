"""Non-regression: reconcile_counts.py standalone exit code = same script
invoked via the registry_drift plugin, for identical input."""
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "registry_drift.py"
)

STUB_TEMPLATE = textwrap.dedent("""
    import sys
    sys.stdout.write({stdout!r})
    sys.stderr.write({stderr!r})
    sys.exit({code})
""")


@pytest.mark.regression
@pytest.mark.parametrize("exit_code", [0, 1, 2])
def test_exit_code_is_preserved(tmp_path: Path, exit_code: int):
    pi = tmp_path / "ProjectIndex"
    pi.mkdir()
    stub_src = STUB_TEMPLATE.format(stdout="ok\n", stderr="", code=exit_code)
    stub_path = pi / "reconcile_counts.py"
    stub_path.write_text(stub_src, encoding="utf-8")

    standalone = subprocess.run(
        [sys.executable, str(stub_path)],
        capture_output=True, text=True, cwd=str(pi),
    )
    assert standalone.returncode == exit_code

    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    verdicts = rule.check(ctx)

    if exit_code == 0:
        assert verdicts == [], "exit 0 must produce zero verdicts"
    else:
        assert len(verdicts) == 1, f"non-zero exit must produce one BLOCK verdict"
        assert verdicts[0].severity == Severity.BLOCK
