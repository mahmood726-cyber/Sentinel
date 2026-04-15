"""Regression tests for P0-hardcoded-local-path scan scope.

Covers two 2026-04-14 follow-ups from the portfolio cleanup:

1. **Self-reference exclude** — Sentinel's own output files (STUCK_FAILURES.md,
   sentinel-findings.md, and their .jsonl siblings) must not produce BLOCKs
   when they quote a matched hardcoded-path string. Without this, every scan
   after the first produces an ever-growing cascade of self-reference findings.

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


def test_sentinel_findings_md_is_not_scanned(tmp_path: Path):
    """Sentinel's renamed WARN output (sentinel-findings.md, ex
    review-findings.md — renamed to avoid collision with /review skill)
    must be excluded from scan."""
    (tmp_path / "sentinel-findings.md").write_text(
        "[WARN] P1-unpopulated-placeholder src/x.py:5 C:/Users/user/foo\n",
        encoding="utf-8",
    )
    assert _scan(tmp_path) == [], "sentinel-findings.md must be excluded"


def test_legacy_review_findings_md_is_also_not_scanned(tmp_path: Path):
    """Pre-rename artifacts (review-findings.md) may still exist on disk in
    repos that ran Sentinel before the rename. They must remain excluded
    so old output doesn't become a BLOCK cascade after upgrade."""
    (tmp_path / "review-findings.md").write_text(
        "[BLOCK] P0-hardcoded-local-path src/x.py:5 C:/Users/user/foo\n",
        encoding="utf-8",
    )
    assert _scan(tmp_path) == [], "legacy review-findings.md must also be excluded"


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


def test_docs_superpowers_specs_excluded(tmp_path: Path):
    """Superpowers specs under docs/superpowers/specs/ are design documents
    that legitimately quote local paths as examples (commit 5eaa7d0)."""
    specs = tmp_path / "docs" / "superpowers" / "specs"
    specs.mkdir(parents=True)
    (specs / "2026-04-14-design.md").write_text(
        "Example layout: `C:/Users/user/project/src/main.py`\n",
        encoding="utf-8",
    )
    assert _scan(tmp_path) == [], "docs/superpowers/specs/** must be excluded"


def test_docs_superpowers_plans_excluded(tmp_path: Path):
    """Superpowers plans under docs/superpowers/plans/ are implementation
    plans that quote paths (commit 5eaa7d0)."""
    plans = tmp_path / "docs" / "superpowers" / "plans"
    plans.mkdir(parents=True)
    (plans / "2026-04-14-plan.md").write_text(
        "Task 3: edit `C:/Users/user/project/engine.py::run()`\n",
        encoding="utf-8",
    )
    assert _scan(tmp_path) == [], "docs/superpowers/plans/** must be excluded"


def test_excludes_apply_under_real_git_tracked_set(tmp_path: Path):
    """P2-7: All other tests use tmp_path without .git/, so _git_tracked_files
    returns None and the rglob fallback is exercised. Real pre-push runs go
    through the git-tracked-set path. This test initialises a real git repo
    and confirms the exclude mechanism works on the tracked set too."""
    import subprocess
    subprocess.run(["git", "init", "--quiet"], cwd=str(tmp_path), check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@sentinel"],
        cwd=str(tmp_path), check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Sentinel Test"],
        cwd=str(tmp_path), check=True, capture_output=True,
    )
    specs = tmp_path / "docs" / "superpowers" / "specs"
    specs.mkdir(parents=True)
    (specs / "design.md").write_text(
        "Example: `C:/Users/user/project.py`\n", encoding="utf-8",
    )
    (tmp_path / "README.md").write_text(
        "See `C:/Users/user/other.py`\n", encoding="utf-8",
    )
    subprocess.run(
        ["git", "add", "."], cwd=str(tmp_path), check=True, capture_output=True,
    )
    verdicts = _scan(tmp_path)
    assert len(verdicts) == 1
    assert verdicts[0].file == "README.md", (
        "README.md must fire (in tracked set), specs/design.md must not fire "
        f"(excluded). Got: {[v.file for v in verdicts]}"
    )


def test_skip_marker_in_markdown_excludes_file(tmp_path: Path):
    """A file with `<!-- sentinel:skip-file -->` in the first 1KB is
    skipped by all rules. Used for rule-doc files that legitimately
    quote the patterns Sentinel flags (dogfooding)."""
    (tmp_path / "lessons.md").write_text(
        "# Rules doc\n"
        "<!-- sentinel:skip-file — this file documents the patterns we flag -->\n"
        "- Never ship `C:\\Users\\user\\data.py` paths.\n",
        encoding="utf-8",
    )
    assert _scan(tmp_path) == [], "file with skip marker must be excluded"


def test_skip_marker_in_python_comment_works(tmp_path: Path):
    """`# sentinel:skip-file` in a Python file also works — we do
    substring match, not syntax-aware parsing."""
    (tmp_path / "rule_test_fixture.py").write_text(
        "# sentinel:skip-file — fixture for testing rule patterns\n"
        'BAD_PATH = "C:\\\\Users\\\\user\\\\data.py"\n',
        encoding="utf-8",
    )
    assert _scan(tmp_path) == [], "python file with skip marker must be excluded"


def test_skip_marker_must_be_in_first_1kb(tmp_path: Path):
    """The marker check scans only the first SKIP_MARKER_SCAN_BYTES (1KB).
    A marker deep in a large file does NOT skip — otherwise a malicious
    file could embed the marker in the middle and bypass all rules."""
    padding = "x" * 2000
    (tmp_path / "sneaky.md").write_text(
        f"# innocent header\n{padding}\n"
        "<!-- sentinel:skip-file -->\n"
        "**Path:** C:\\Users\\user\\data.py\n",
        encoding="utf-8",
    )
    verdicts = _scan(tmp_path)
    assert len(verdicts) == 1, "marker beyond 1KB must not skip the file"


def test_no_skip_marker_still_fires(tmp_path: Path):
    """Negative control: a file WITHOUT the marker still gets scanned."""
    (tmp_path / "normal.md").write_text(
        "# Normal doc\n"
        "Source: `C:/Users/user/project.py`\n",
        encoding="utf-8",
    )
    verdicts = _scan(tmp_path)
    assert len(verdicts) == 1


def test_wiki_dir_excluded(tmp_path: Path):
    """Auto-generated portfolio wiki entries (Overmind writes
    wiki/<project>.md with `**Path:** C:\\...` lines describing where
    each project lives on disk) are DATA, not code. Excluded to drain
    ~80 false-positive BLOCKs from Overmind's STUCK_FAILURES.md."""
    wiki = tmp_path / "wiki"
    wiki.mkdir()
    (wiki / "some-project.md").write_text(
        "# some-project\n"
        "- **Path:** C:\\Users\\user\\Projects\\some-project\n"
        "- **Verdict:** PASS\n",
        encoding="utf-8",
    )
    assert _scan(tmp_path) == [], "wiki/** must be excluded (auto-gen portfolio data)"


def test_nested_wiki_dir_excluded(tmp_path: Path):
    """Wiki directories at any depth are excluded (e.g. docs/wiki/,
    overmind/wiki/)."""
    nested = tmp_path / "tools" / "overmind" / "wiki"
    nested.mkdir(parents=True)
    (nested / "entry.md").write_text(
        "**Path:** C:\\Users\\user\\Projects\\x\n",
        encoding="utf-8",
    )
    assert _scan(tmp_path) == [], "nested wiki/** must also be excluded"


def test_non_wiki_dir_still_fires(tmp_path: Path):
    """Negative control: a dir called `wikipedia` or `wiki-docs` must
    still fire — the exclude is on `wiki` as a path segment only."""
    other = tmp_path / "wiki-docs"
    other.mkdir()
    (other / "entry.md").write_text(
        "**Path:** C:\\Users\\user\\Projects\\x\n",
        encoding="utf-8",
    )
    verdicts = _scan(tmp_path)
    assert len(verdicts) == 1
    assert verdicts[0].file == "wiki-docs/entry.md"


def test_docs_other_path_still_fires(tmp_path: Path):
    """Negative control: docs/ outside superpowers/specs|plans/ is NOT
    excluded — catches regressions that broaden the exclude too far."""
    other = tmp_path / "docs" / "architecture"
    other.mkdir(parents=True)
    (other / "overview.md").write_text(
        "See `C:/Users/user/data/notes.md`\n",
        encoding="utf-8",
    )
    verdicts = _scan(tmp_path)
    assert len(verdicts) == 1
    assert verdicts[0].file == "docs/architecture/overview.md"
