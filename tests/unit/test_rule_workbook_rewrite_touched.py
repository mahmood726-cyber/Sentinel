import textwrap
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "workbook_rewrite_touched.py"
)

WORKBOOK = textwrap.dedent("""\
    ENTRY 1/3
    CURRENT BODY:
      Lorem ipsum dolor sit amet.
    YOUR REWRITE:
      This is the user's protected rewrite.
      Second line of the rewrite.
    SUBMITTED: [ ]
    ---
    ENTRY 2/3
    CURRENT BODY:
      Body 2.
    YOUR REWRITE:
      Rewrite 2 line 1.
    SUBMITTED: [x]
""")


DIFF_TOUCHES_YOUR_REWRITE = textwrap.dedent("""\
    diff --git a/rewrite-workbook.txt b/rewrite-workbook.txt
    index 0000000..1111111 100644
    --- a/rewrite-workbook.txt
    +++ b/rewrite-workbook.txt
    @@ -5,1 +5,1 @@ ENTRY 1/3
    -  This is the user's protected rewrite.
    +  TAMPERED LINE BY CLAUDE
    """)


DIFF_TOUCHES_CURRENT_BODY_ONLY = textwrap.dedent("""\
    diff --git a/rewrite-workbook.txt b/rewrite-workbook.txt
    index 0000000..1111111 100644
    --- a/rewrite-workbook.txt
    +++ b/rewrite-workbook.txt
    @@ -3,1 +3,1 @@ CURRENT BODY
    -  Lorem ipsum dolor sit amet.
    +  Improved body text.
    """)


def _setup(tmp_path: Path) -> Path:
    (tmp_path / "rewrite-workbook.txt").write_text(WORKBOOK, encoding="utf-8")
    return tmp_path


def test_workbook_rule_blocks_when_rewrite_touched(tmp_path: Path, monkeypatch):
    repo = _setup(tmp_path)
    rule = load_plugin_rule(PLUGIN_PATH)

    # The plugin reads from an env var SENTINEL_TEST_DIFF to inject diff text.
    monkeypatch.setenv("SENTINEL_TEST_DIFF", DIFF_TOUCHES_YOUR_REWRITE)

    verdicts = rule.check(RepoContext(repo_root=repo, mode=ScanMode.REPO))
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "P0-workbook-rewrite-touched"
    assert verdicts[0].severity == Severity.BLOCK


def test_workbook_rule_silent_when_only_current_body_touched(tmp_path, monkeypatch):
    repo = _setup(tmp_path)
    rule = load_plugin_rule(PLUGIN_PATH)
    monkeypatch.setenv("SENTINEL_TEST_DIFF", DIFF_TOUCHES_CURRENT_BODY_ONLY)
    assert rule.check(RepoContext(repo_root=repo, mode=ScanMode.REPO)) == []


def test_workbook_rule_silent_when_no_workbook_in_repo(tmp_path, monkeypatch):
    # Empty repo, no rewrite-workbook.txt
    rule = load_plugin_rule(PLUGIN_PATH)
    monkeypatch.setenv("SENTINEL_TEST_DIFF", DIFF_TOUCHES_YOUR_REWRITE)
    assert rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)) == []
