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


def test_hardcoded_local_path_fires_on_d_drive(tmp_path: Path):
    """lessons.md#code-quality: data may live on C: or D:. P1-5 fix must
    cover D:\\projects\\... and similar. ad65952 only covered C:\\Users\\."""
    (tmp_path / "loader.py").write_text(
        'DATA_DIR = r"D:\\projects\\aact\\snapshot.db"\n',
        encoding="utf-8",
    )
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.BLOCK


def test_hardcoded_local_path_fires_case_insensitive(tmp_path: Path):
    """PowerShell Get-Location emits lowercase drive letter; the pre-P1-4
    regex was case-sensitive and missed `c:\\users\\...`."""
    (tmp_path / "run.ps1").write_text(
        r'cd "c:\users\mahmood\projects"' + "\n",
        encoding="utf-8",
    )
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert len(verdicts) == 1


def test_hardcoded_local_path_fires_on_macos_users(tmp_path: Path):
    """macOS /Users/<name>/... — analogue of /home/ on Linux."""
    (tmp_path / "config.sh").write_text(
        'export DATA=/Users/alice/project/data.csv\n',
        encoding="utf-8",
    )
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert len(verdicts) == 1


def test_hardcoded_local_path_fires_on_onedrive_path(tmp_path: Path):
    """OneDrive corporate paths like C:\\Users\\user\\OneDrive - NHS\\... are
    prevalent in the portfolio (per lessons.md) and must fire."""
    (tmp_path / "validator.R").write_text(
        'CSV_DIR <- "C:/Users/user/OneDrive - NHS/Documents/pairwise"\n',
        encoding="utf-8",
    )
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert len(verdicts) == 1


def test_hardcoded_local_path_silent_on_windows_system_paths(tmp_path: Path):
    """Negative control: C:\\Windows\\System32 and C:\\tmp are NOT user paths
    and must not fire. Option (b) discriminates via the path segment after
    the drive letter (Users|projects|ProgramData|OneDrive only)."""
    (tmp_path / "detector.py").write_text(
        'SYS = "C:/Windows/System32"\n'
        'TMP = "C:/tmp/workdir"\n'
        'PROGRAM_FILES = "C:/Program Files/app/bin"\n',
        encoding="utf-8",
    )
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert verdicts == [], f"system paths must not fire: {[v.detail for v in verdicts]}"


def test_hardcoded_local_path_silent_on_keyboard_shortcut_prose(tmp_path: Path):
    """Regression for false positive surfaced 2026-04-16 against
    Finrenone/MANUSCRIPT_LIVINGMETA.md and F1000_LivingMeta_Article_v2.md:
    accessibility prose like 'ArrowLeft/Right/Home/End' was flagged as a
    hardcoded path because the case-insensitive `/home/[a-z_]` alternative
    matched `/Home/End` mid-string. Real /home/user/ and /Users/alice paths
    must still fire (covered by other tests); slash-separated word-prose
    must NOT. Fix: anchor the unix-path alternatives to start-of-string,
    whitespace, quote, paren, equals, or colon."""
    (tmp_path / "manuscript.md").write_text(
        "All eight tab panels are keyboard-navigable "
        "(ArrowLeft/Right/Home/End), screen reader accessible.\n"
        "Sort order: Up/Down/Left/Right/PageUp/PageDown/Users/Items.\n",
        encoding="utf-8",
    )
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert verdicts == [], f"keyboard-shortcut prose must not fire: {[v.detail for v in verdicts]}"


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
