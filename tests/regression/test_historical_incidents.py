"""Regression corpus: each test encodes a REAL past incident that Sentinel
now blocks. If a rule is ever weakened in a way that lets one of these
through again, a test here fires.

This is deliberately a catalog of historical failures, not synthetic
examples. The content in each fixture is either:
  - verbatim from the actual commit/file that caused the incident, with
    identifiers stripped where appropriate; or
  - the minimal excerpt from a documented lesson in
    `C:\\Users\\user\\.claude\\rules\\lessons.md` that describes the bug.

Each test's docstring names the incident, the date, and the rule that
should catch it now. If you weaken a rule and one of these starts
passing (i.e. doesn't fire), you have re-introduced a known-broken
class of bug.

Naming: test_<rule-id-suffix>_<short-incident-name>. Rules are loaded
directly from the shipping YAML/plugin files (no duplication).
"""
from __future__ import annotations
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.yaml_loader import load_yaml_rule


SENTINEL_ROOT = Path(__file__).resolve().parents[2]
YAML_DIR = SENTINEL_ROOT / "sentinel" / "rules" / "yaml"


def _load(rule_name: str):
    """Load a YAML rule by filename stem (e.g. 'P0-hardcoded-local-path')."""
    return load_yaml_rule(YAML_DIR / f"{rule_name}.yaml")


# ---------------------------------------------------------------------------
# P0-hardcoded-local-path — real incidents of `C:\Users\...` leaking into
# deployable code or shipped docs. Multiple were resolved 2026-04-14 across
# 5 warn-mode repos (50 BLOCKs → 0).
# ---------------------------------------------------------------------------

def test_hardcoded_local_path__onedrive_leak_in_r_validation_script(tmp_path):
    """Incident: metasprint r_metafor_crossval.R (2026-04-14) hardcoded an
    OneDrive path as the CSV_DIR. Had to be moved to a config module.
    Real fix: C:/Models/metasprint-autopilot/validation/_paths.py."""
    (tmp_path / "r_metafor_crossval.R").write_text(
        'CSV_DIR <- "C:/Users/user/OneDrive - NHS/Documents/pairwise"\n',
        encoding="utf-8",
    )
    verdicts = _load("P0-hardcoded-local-path").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.BLOCK
    assert verdicts[0].file == "r_metafor_crossval.R"


def test_hardcoded_local_path__denominator_csv_provenance(tmp_path):
    """Incident: Denominator_Calibrated_Living_NMA × 16 JSON provenance
    lines leaked user paths (2026-04-14). Fixed by switching to basename."""
    (tmp_path / "publication_export.csv").write_text(
        "id,source_file\nrow1,C:/Users/user/DOAC_AF_REVIEW.html\n",
        encoding="utf-8",
    )
    verdicts = _load("P0-hardcoded-local-path").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert len(verdicts) == 1
    assert verdicts[0].file == "publication_export.csv"


def test_hardcoded_local_path__proportionfirstprinciples_csv_load(tmp_path):
    """Incident: huge_data_stress_test.py:53 (2026-04-15). Hardcoded path
    in stress-test research code. Refactored to Path.home() + env-var
    override in home-config commit 38cc488e. The ORIGINAL content is
    below — rule must fire."""
    src = tmp_path / "huge_data_stress_test.py"
    src.write_text(
        'import pandas as pd\n'
        'df = pd.read_csv(r"C:\\Users\\user\\Projects\\scratch-drma\\data\\sim.csv")\n',
        encoding="utf-8",
    )
    verdicts = _load("P0-hardcoded-local-path").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert len(verdicts) == 1


def test_hardcoded_local_path__readme_example_flagged(tmp_path):
    """Incident: Sentinel's own README.md (2026-04-15 self-scan) had
    `python -m sentinel scan --repo C:/Projects/shifaa` as the example.
    Caught by the widened P0 regex; fixed to `/path/to/your/repo`."""
    (tmp_path / "README.md").write_text(
        "## Quickstart\n"
        "python -m sentinel scan --repo C:/Projects/shifaa\n",
        encoding="utf-8",
    )
    verdicts = _load("P0-hardcoded-local-path").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert len(verdicts) == 1
    assert "shifaa" in verdicts[0].detail


def test_hardcoded_local_path__d_drive_data_snapshot(tmp_path):
    """Incident class: AACT snapshot paths on D: drive (lessons.md
    2026-04-14 entry). The original regex was case-sensitive on C: and
    missed D: entirely; P1-5 fix today added D: + case-insensitive +
    macOS /Users."""
    (tmp_path / "loader.py").write_text(
        'DATA = r"D:\\projects\\aact\\snapshot.db"\n', encoding="utf-8"
    )
    verdicts = _load("P0-hardcoded-local-path").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert len(verdicts) == 1


# ---------------------------------------------------------------------------
# P0-placeholder-hmac — placeholder signatures shipping as real crypto.
# lessons.md#cryptography--signing-learned-2026-04-14 captured the original
# TruthCert incident: `cert_id` was used as HMAC key, and cert bundles
# shipped with `"signature_placeholder": "SIG_RSA_SHA256_..."` strings.
# ---------------------------------------------------------------------------

def test_placeholder_hmac__truthcert_bundle_sig_literal(tmp_path):
    """Incident: early TruthCert cert bundles shipped
    `"signature_placeholder": "SIG_RSA_SHA256_mock"` as real crypto.
    Anyone seeing the output could forge. Replaced with real HMAC via
    TRUTHCERT_HMAC_KEY env."""
    (tmp_path / "cert_bundle.json").write_text(
        '{\n'
        '  "cert_id": "abc123",\n'
        '  "signature_placeholder": "SIG_RSA_SHA256_mock_bytes_32bytes_xxxxx"\n'
        '}\n',
        encoding="utf-8",
    )
    verdicts = _load("P0-placeholder-hmac").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert len(verdicts) >= 1
    assert verdicts[0].severity == Severity.BLOCK


def test_placeholder_hmac__scaffolding_sig_marker(tmp_path):
    """Incident class: auto-generated scaffolding that emitted
    `SIG_RSA_SHA256_` prefix strings as fake sigs must not ship in
    production bundles."""
    (tmp_path / "emit.py").write_text(
        'def fake_sign(): return "SIG_RSA_SHA256_pending_real_key"\n',
        encoding="utf-8",
    )
    verdicts = _load("P0-placeholder-hmac").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert len(verdicts) == 1


# ---------------------------------------------------------------------------
# P1-unpopulated-placeholder — Jinja/Mustache placeholders, REPLACE_ME,
# __PLACEHOLDER__, TBD:, XXX: shipping in deployable HTML/docs.
# Pre-ad65952 regex was too loose (matched CSS braces); post-P0-1 regex
# is too strict if we regress. Both classes covered.
# ---------------------------------------------------------------------------

def test_unpopulated_placeholder__jinja_filter_must_fire(tmp_path):
    """Regression from P0-1 (2026-04-15): ad65952 tightened the regex to
    bare-identifier-only, which rejected real Jinja `{{ x|filter }}`.
    The replacement regex must match filter syntax."""
    (tmp_path / "template.html").write_text(
        "<p>Hello {{ user|upper }}</p>\n", encoding="utf-8"
    )
    verdicts = _load("P1-unpopulated-placeholder").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert len(verdicts) == 1


def test_unpopulated_placeholder__css_fstring_must_not_fire(tmp_path):
    """Symmetric regression: pre-ad65952 regex matched `{{background:#fff}}`
    inside Python f-strings as false positives. The CSS escape must NOT
    fire — otherwise dashboard CLI generators (sentinel/cli/dashboard.py)
    produce ~10 false-positive WARNs per run."""
    (tmp_path / "dashboard.py").write_text(
        'style = f"table{{width:100%;border-collapse:collapse}}"\n',
        encoding="utf-8",
    )
    verdicts = _load("P1-unpopulated-placeholder").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert verdicts == []


def test_unpopulated_placeholder__replace_me_literal(tmp_path):
    """Incident class: `REPLACE_ME` / `__PLACEHOLDER__` / `TBD:` markers
    that scaffolding emits and then nobody remembers to fill. html-apps.md
    safety checks list this as the #5 common ship-blocker."""
    (tmp_path / "notes.md").write_text(
        "# Project\n\n"
        "Author: REPLACE_ME\n"
        "TBD: add methodology section\n"
        "XXX: benchmarks here\n"
        "Hash: __PLACEHOLDER__\n",
        encoding="utf-8",
    )
    verdicts = _load("P1-unpopulated-placeholder").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    # All 4 literal alternatives must fire
    assert len(verdicts) == 4


# ---------------------------------------------------------------------------
# P1-silent-failure-sentinel — `return "unknown_..."` silent-failure returns
# that hide schema errors. Motivating incident (lessons.md#integration-
# contracts-learned-2026-04-14): MetaReproducer's P0-1 corrupted 465
# reviews because effect_inference.py returned "unknown_ratio" on schema
# mismatch instead of raising.
# ---------------------------------------------------------------------------

def test_silent_failure_sentinel__return_unknown_ratio(tmp_path):
    """Incident: MetaReproducer effect_inference.py (2026-04-14) returned
    "unknown_ratio" on schema mismatch. Silent corruption of 465 reviews."""
    (tmp_path / "effect_inference.py").write_text(
        'def infer(study):\n'
        '    if "hr" not in study:\n'
        '        return "unknown_ratio"\n'
        '    return study["hr"]\n',
        encoding="utf-8",
    )
    verdicts = _load("P1-silent-failure-sentinel").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.WARN


def test_silent_failure_sentinel__silent_sentinel_token(tmp_path):
    """Incident class: `__silent__` / `__fail__` magic strings that silently
    signal failure downstream without raising. Blocked by the same rule."""
    (tmp_path / "parser.py").write_text(
        'def parse_hr(cell):\n'
        '    try:\n'
        '        return float(cell)\n'
        '    except ValueError:\n'
        '        return "__silent__"\n',
        encoding="utf-8",
    )
    verdicts = _load("P1-silent-failure-sentinel").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert len(verdicts) == 1


# ---------------------------------------------------------------------------
# P0-agent-config-version-drift — written 2026-04-15 after I personally
# wrote `v2.1.0` in AGENTS.md while Overmind's pyproject.toml said `3.1.0`.
# ---------------------------------------------------------------------------

def test_agent_config_version_drift__stale_version_in_agents_md(tmp_path, monkeypatch):
    """Incident: AGENTS.md claimed Overmind v2.1.0 while pyproject had
    v3.1.0 for 7+ days (2026-04-15). Only caught by manual audit.
    This rule would have caught it at next push.

    Uses a hardcoded Windows-style path (rule's regex is Windows-only by
    design) and monkeypatches the authoritative version lookup, so the
    test is cross-platform without depending on tmp_path shape.
    """
    import sentinel.rules.plugins.agent_config_version_drift as mod
    real_is_dir = Path.is_dir
    monkeypatch.setattr(Path, "is_dir", lambda self: (
        str(self).replace("\\", "/").startswith("C:/fake") or real_is_dir(self)
    ))
    monkeypatch.setattr(mod, "_authoritative_version", lambda _p: "3.1.0")
    (tmp_path / "AGENTS.md").write_text(
        "# AGENTS\n\n"
        "- **Overmind** (`C:/fake/overmind`, v2.1.0) is the portfolio verifier.\n",
        encoding="utf-8",
    )
    from sentinel.rules.plugins.agent_config_version_drift import check
    verdicts = check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert len(verdicts) == 1
    assert "v2.1.0" in verdicts[0].detail
    assert "v3.1.0" in verdicts[0].detail


# ---------------------------------------------------------------------------
# Integration contract regression — the Sentinel→Overmind filename rename
# that 3572ac4 caught in Overmind after Sentinel d23b6a8. If Sentinel
# renames WARN_MD again without updating Overmind's aggregator, this
# class of bug recurs. The end-to-end contract test in Overmind catches
# it there; here we assert Sentinel's own constants are stable.
# ---------------------------------------------------------------------------

def test_output_filenames_contract_stable():
    """Incident: d23b6a8 renamed review-findings.md → sentinel-findings.md.
    Overmind's aggregator was initially unaware; 3572ac4 fixed Overmind.
    If we rename AGAIN, Overmind breaks again unless its constants are
    also updated. Canonical names must live in sentinel.io.paths and
    include LEGACY_FILENAMES for migration-window compatibility."""
    from sentinel.io import paths
    # These are the contract: Overmind's _WARN_JSONL_NAMES etc. must list
    # these first, with legacy names as fallback (tested in Overmind).
    assert paths.BLOCK_MD == "STUCK_FAILURES.md"
    assert paths.BLOCK_JSONL == "STUCK_FAILURES.jsonl"
    assert paths.WARN_MD == "sentinel-findings.md"
    assert paths.WARN_JSONL == "sentinel-findings.jsonl"
    # Legacy names must include the pre-rename WARN name for at least one
    # migration cycle so Overmind's aggregator can still read old output.
    assert "review-findings.md" in paths.LEGACY_FILENAMES
    assert "review-findings.jsonl" in paths.LEGACY_FILENAMES


# ---------------------------------------------------------------------------
# Skip-file marker safety — added 2026-04-15 to drain dogfooding noise
# from rule-docs files. Must not accept markers hidden deep in a file
# (would be a bypass).
# ---------------------------------------------------------------------------

def test_skip_marker__must_be_in_first_1kb_not_deeper(tmp_path):
    """Regression guard: the skip-file marker scans only the first 1KB
    (SKIP_MARKER_SCAN_BYTES). If we ever widen that window, a malicious
    or careless file could embed the marker deep inside to bypass. This
    test locks the depth limit."""
    padding = "x" * 2000  # well over 1KB
    (tmp_path / "sneaky.md").write_text(
        f"# innocent-looking header\n{padding}\n"
        "<!-- sentinel:skip-file -->\n"
        "**Path:** C:\\Users\\user\\secrets\\data.py\n",
        encoding="utf-8",
    )
    verdicts = _load("P0-hardcoded-local-path").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert len(verdicts) == 1, (
        "marker past 1KB must NOT skip the file — would be a depth-bypass"
    )


# ---------------------------------------------------------------------------
# Auto-gen directory excludes — Overmind's wiki/** and data/nightly_reports
# etc. are data, not code. Rule must not fire on them.
# ---------------------------------------------------------------------------

def test_wiki_dir_excluded__overmind_health_cards(tmp_path):
    """Incident: pre-09341fe Sentinel scan of Overmind produced 3029
    BLOCKs, 2830 from wiki/*.md health cards embedding **Path:** C:\\...
    as portfolio metadata. After the exclude landed, Overmind scan
    dropped to 199. Canonical example of auto-gen-is-data."""
    wiki = tmp_path / "wiki"
    wiki.mkdir()
    (wiki / "advanced-nma-pooling-090cb3c6.md").write_text(
        "# advanced-nma-pooling\n\n"
        "- **Path:** C:\\Users\\user\\OneDrive\\Backups\\Models\\advanced-nma-pooling\n"
        "- **Verdict:** PASS\n",
        encoding="utf-8",
    )
    verdicts = _load("P0-hardcoded-local-path").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert verdicts == [], "wiki/** must be excluded (auto-gen portfolio data)"


# ---------------------------------------------------------------------------
# WARN-mode install-hook target-repo gitignore — 2026-04-15 incident:
# Sentinel's install-hook now auto-adds its output filenames to the
# target .gitignore. Before that landed, users could commit STUCK_FAILURES.md
# (containing absolute paths) and self-violate P0 on next scan.
# ---------------------------------------------------------------------------

def test_install_hook__gitignore_backfill_runs():
    """Incident: before ensure_sentinel_gitignored() landed (2026-04-15
    commit d23b6a8), hook-installed repos had no default gitignore of
    Sentinel output. A user running `git add .` after a scan could
    commit paths that fail P0 on rescan. Verify the installer does
    append on install."""
    from sentinel.hook.installer import ensure_sentinel_gitignored
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        (repo / ".git").mkdir()  # minimum for install
        (repo / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
        ensure_sentinel_gitignored(repo)
        content = (repo / ".gitignore").read_text(encoding="utf-8")
        assert "node_modules/" in content  # existing preserved
        assert "STUCK_FAILURES.md" in content
        assert "sentinel-findings.md" in content


# ---------------------------------------------------------------------------
# P1-empty-dataframe-access — `.iloc[0]` / `.iloc[-1]` / `.values[0]` without
# a guarded preceding .empty / len() check. Named as one of the top-5 repeat
# defects in MEMORY.md#top-5-cross-project-defects. Every "X trials met the
# criterion" CT.gov audit that returned an empty DataFrame silently raised
# IndexError at the first .iloc[0].
# ---------------------------------------------------------------------------

def test_empty_df__iloc_zero_flagged(tmp_path):
    """Incident class: pandas `.iloc[0]` on a filter result that can be
    empty. CT.gov audit scripts repeatedly hit this when an NCT filter
    returned zero rows; the access raised IndexError rather than returning
    a typed 'no matches' response."""
    (tmp_path / "audit.py").write_text(
        "import pandas as pd\n"
        "def first_match(df, nct):\n"
        "    matched = df[df.nct_id == nct]\n"
        "    return matched.iloc[0]\n",
        encoding="utf-8",
    )
    verdicts = _load("P1-empty-dataframe-access").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.WARN


def test_empty_df__iloc_minus_one_flagged(tmp_path):
    """Incident class: `.iloc[-1]` is the mirror bug — "last row" of a
    potentially empty DataFrame. Same IndexError surface."""
    (tmp_path / "pipeline.py").write_text(
        "def latest(df):\n"
        "    return df.iloc[-1]\n",
        encoding="utf-8",
    )
    verdicts = _load("P1-empty-dataframe-access").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert len(verdicts) == 1


def test_empty_df__values_zero_flagged(tmp_path):
    """Incident class: `series.values[0]` — numpy-backed positional access
    on an empty Series, same IndexError surface as pandas .iloc[0]."""
    (tmp_path / "compute.py").write_text(
        "def first_val(s):\n"
        "    return s.values[0]\n",
        encoding="utf-8",
    )
    verdicts = _load("P1-empty-dataframe-access").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert len(verdicts) == 1


def test_empty_df__tests_dir_excluded(tmp_path):
    """Tests legitimately construct known-non-empty fixtures and access
    `.iloc[0]` without guards. COMMON_EXCLUDES covers tests/**; this
    regression asserts that exclusion still works for this new rule."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_math.py").write_text(
        "import pandas as pd\n"
        "def test_foo():\n"
        "    df = pd.DataFrame({'x': [1]})\n"
        "    assert df.iloc[0].x == 1\n",
        encoding="utf-8",
    )
    verdicts = _load("P1-empty-dataframe-access").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert verdicts == [], (
        f"tests/ must be excluded by COMMON_EXCLUDES, got {verdicts!r}"
    )


def test_empty_df__skip_file_marker_bypasses(tmp_path):
    """Generated-reporting files that are provably safe can opt out via
    `sentinel:skip-file`. This confirms the standard suppression path
    works for the new rule."""
    (tmp_path / "report_gen.py").write_text(
        "# sentinel:skip-file\n"
        "# Known-safe generator: inputs are always non-empty by contract.\n"
        "def render(df):\n"
        "    return df.iloc[0]\n",
        encoding="utf-8",
    )
    verdicts = _load("P1-empty-dataframe-access").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert verdicts == []


def test_empty_df__iat_not_flagged(tmp_path):
    """`.iat[0]` is an acceptable alternative when the caller has already
    verified non-emptiness — it's the documented fix_hint. Rule must not
    fire on `.iat[0]`, only on `.iloc[0]` / `.values[0]`."""
    (tmp_path / "ok.py").write_text(
        "def safe(df):\n"
        "    if df.empty:\n"
        "        return None\n"
        "    return df.iat[0, 0]\n",
        encoding="utf-8",
    )
    verdicts = _load("P1-empty-dataframe-access").check(
        RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    )
    assert verdicts == []
