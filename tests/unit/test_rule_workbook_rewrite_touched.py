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


# ---------------------------------------------------------------------------
# REAL-FORMAT tests, added 2026-08-30.
#
# The three tests above all passed while the rule protected 11 of 1,875 rewrite
# blocks on the live workbook (65 of 122,369 lines, 0.1%). They passed because
# their fixture uses the bare `YOUR REWRITE:` header, which the live file uses
# 11 times, while it uses `YOUR REWRITE (at most 156 words, 7 sentences):`
# 1,864 times -- and the rule matched an exact-prefix literal:
#
#     "YOUR REWRITE (at most 156 words, 7 sentences):".startswith("YOUR REWRITE:")
#     -> False
#
# The fixture below is the shape the workbook actually has, including the
# SUBMISSION METADATA trailer. A test written from the implementation instead
# of from the artefact is how a rule guards 0.1% of what it names and still
# reports green.
# ---------------------------------------------------------------------------

REAL_WORKBOOK = textwrap.dedent("""\
    ======================================================================
    [501/1873] REALFMT
    TITLE: A real-format entry
    CURRENT BODY (156 words):
    Body sentence that the AI may edit freely.

    YOUR REWRITE (at most 156 words, 7 sentences):
    The author's protected rewrite sentence.

    SUBMISSION METADATA:
      Target journal: Synthesis
      Manuscript license: CC-BY-4.0.
      Code license: MIT.

    SUBMITTED: [ ]

    ======================================================================
""")


def _diff(line_no: int, old: str, new: str) -> str:
    return textwrap.dedent(f"""\
        diff --git a/rewrite-workbook.txt b/rewrite-workbook.txt
        index 0000000..1111111 100644
        --- a/rewrite-workbook.txt
        +++ b/rewrite-workbook.txt
        @@ -{line_no},1 +{line_no},1 @@
        -{old}
        +{new}
        """)


def _real_repo(tmp_path: Path) -> Path:
    (tmp_path / "rewrite-workbook.txt").write_text(REAL_WORKBOOK, encoding="utf-8")
    return tmp_path


def test_parenthetical_header_is_recognised(tmp_path: Path):
    """The header the live workbook uses 1,864 times must produce a protected
    range. This is the whole defect: a literal where a structure was needed."""
    rule = load_plugin_rule(PLUGIN_PATH)
    import importlib.util
    spec = importlib.util.spec_from_file_location("wrt_mod", PLUGIN_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    ranges = mod._protected_line_ranges(REAL_WORKBOOK)
    assert ranges, (
        "no protected range for `YOUR REWRITE (at most 156 words, 7 sentences):` "
        "- the rule is blind to the header the workbook actually uses"
    )
    assert rule.severity == Severity.BLOCK


def test_blocks_edit_inside_parenthetical_rewrite_block(tmp_path: Path, monkeypatch):
    repo = _real_repo(tmp_path)
    rule = load_plugin_rule(PLUGIN_PATH)
    monkeypatch.setenv("SENTINEL_TEST_DIFF", _diff(
        8, "The author's protected rewrite sentence.", "TAMPERED BY A TOOL"))
    verdicts = rule.check(RepoContext(repo_root=repo, mode=ScanMode.REPO))
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.BLOCK


def test_silent_on_current_body_edit_in_real_format(tmp_path: Path, monkeypatch):
    repo = _real_repo(tmp_path)
    rule = load_plugin_rule(PLUGIN_PATH)
    monkeypatch.setenv("SENTINEL_TEST_DIFF", _diff(
        5, "Body sentence that the AI may edit freely.", "Improved body text."))
    assert rule.check(RepoContext(repo_root=repo, mode=ScanMode.REPO)) == []


def test_silent_on_publish_metadata_edit(tmp_path: Path, monkeypatch):
    """A publish commit appends an `OJS:` line and flips SUBMITTED inside the
    SUBMISSION METADATA trailer. Widening the header match WITHOUT adding
    `SUBMISSION METADATA:` to the terminators makes every protected range
    swallow that trailer, and this rule then blocks every publish -- the worse
    defect one step down."""
    repo = _real_repo(tmp_path)
    rule = load_plugin_rule(PLUGIN_PATH)
    monkeypatch.setenv("SENTINEL_TEST_DIFF", _diff(
        15, "SUBMITTED: [ ]", "SUBMITTED: [x]"))
    assert rule.check(RepoContext(repo_root=repo, mode=ScanMode.REPO)) == [], (
        "a publish-metadata edit must not block; the protected range is "
        "over-broad"
    )
