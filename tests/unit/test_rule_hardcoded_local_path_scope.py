"""Regression tests for P0-hardcoded-local-path scan scope.

Covers two 2026-04-14 follow-ups from the portfolio cleanup:

1. **Self-reference exclude** — Sentinel's own output files (STUCK_FAILURES.md,
   review-findings.md, and their .jsonl siblings) must not produce BLOCKs when
   they quote a matched hardcoded-path string. Without this, every scan after
   the first produces an ever-growing cascade of self-reference findings.

2. **File-type scope** — The rule must scan .md / .csv / .R / .ps1 because
   Mahmood's portfolio repeatedly leaks user paths through those file types:
   README.md provenance lines (Denominator), CSV upstreams (Denominator
   raw_sources), R validation scripts (metasprint r_metafor_crossval.R),
   PowerShell nightly jobs (metasprint truthcert1_work/*.ps1).
"""
from pathlib import Path
from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.yaml_loader import load_yaml_rule


RULE_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "yaml" / "P0-hardcoded-local-path.yaml"
)


def _scan(tmp_path: Path):
    rule = load_yaml_rule(RULE_PATH)
    return rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))


def test_stuck_failures_md_is_not_scanned(tmp_path: Path):
    (tmp_path / "STUCK_FAILURES.md").write_text(
        r'- **Detail:** pattern matched: C:\Users\user\data' + "\n",
        encoding="utf-8",
    )
    assert _scan(tmp_path) == [], (
        "Sentinel's own STUCK_FAILURES.md output must not self-flag "
        "(GLOBAL_EXCLUDES regression)."
    )


def test_review_findings_md_is_not_scanned(tmp_path: Path):
    (tmp_path / "review-findings.md").write_text(
        "[BLOCK] P0-hardcoded-local-path src/x.py:5 C:/Users/user/foo\n",
        encoding="utf-8",
    )
    assert _scan(tmp_path) == [], "review-findings.md must be excluded"


def test_nested_stuck_failures_md_is_not_scanned(tmp_path: Path):
    nested = tmp_path / "sub" / "deep"
    nested.mkdir(parents=True)
    (nested / "STUCK_FAILURES.md").write_text(
        "pattern matched: C:/Users/user/x\n", encoding="utf-8",
    )
    assert _scan(tmp_path) == [], "nested STUCK_FAILURES.md must be excluded"


def test_markdown_file_is_scanned(tmp_path: Path):
    """A README.md with a hardcoded user path must fire. Denominator gap."""
    (tmp_path / "README.md").write_text(
        "Source: `C:/Users/user/SGLT2i_HF_REVIEW.html`\n",
        encoding="utf-8",
    )
    verdicts = _scan(tmp_path)
    assert len(verdicts) == 1, f"expected 1 BLOCK on README.md, got {verdicts}"
    assert verdicts[0].severity == Severity.BLOCK
    assert verdicts[0].file == "README.md"


def test_csv_file_is_scanned(tmp_path: Path):
    """CSVs with provenance columns often leak paths. Denominator raw_sources gap."""
    (tmp_path / "publication_export.csv").write_text(
        "id,source_file\nrow1,C:/Users/user/DOAC_AF_REVIEW.html\n",
        encoding="utf-8",
    )
    verdicts = _scan(tmp_path)
    assert len(verdicts) == 1
    assert verdicts[0].file == "publication_export.csv"


def test_r_script_is_scanned(tmp_path: Path):
    """R validation scripts (metasprint r_metafor_crossval.R gap)."""
    (tmp_path / "r_metafor_crossval.R").write_text(
        'CSV_DIR <- "C:/Users/user/OneDrive - NHS/Documents/pairwise"\n',
        encoding="utf-8",
    )
    verdicts = _scan(tmp_path)
    assert len(verdicts) == 1
    assert verdicts[0].file == "r_metafor_crossval.R"


def test_powershell_script_is_scanned(tmp_path: Path):
    """PowerShell nightly jobs (metasprint truthcert1_work/*.ps1 gap)."""
    (tmp_path / "run_nightly.ps1").write_text(
        '& "C:/Users/user/AppData/Local/Programs/Python/Python313/python.exe"' + "\n",
        encoding="utf-8",
    )
    verdicts = _scan(tmp_path)
    assert len(verdicts) == 1
    assert verdicts[0].file == "run_nightly.ps1"


def test_shell_script_is_scanned(tmp_path: Path):
    (tmp_path / "deploy.sh").write_text(
        'cd /home/deploy && ./run.sh\n', encoding="utf-8",
    )
    verdicts = _scan(tmp_path)
    assert len(verdicts) == 1
    assert verdicts[0].file == "deploy.sh"


def test_txt_file_is_scanned(tmp_path: Path):
    (tmp_path / "notes.txt").write_text(
        "data was loaded from C:/Users/user/project/data.csv\n",
        encoding="utf-8",
    )
    verdicts = _scan(tmp_path)
    assert len(verdicts) == 1
    assert verdicts[0].file == "notes.txt"
