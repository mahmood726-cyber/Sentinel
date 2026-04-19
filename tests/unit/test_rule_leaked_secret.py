"""Tests for P1-leaked-secret.

Verifies the plugin fires on each credential class, respects
false-positive shields, and stays at WARN severity (not BLOCK) so
historical false positives don't break existing pushes.
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "leaked_secret.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def test_clean_repo_no_verdicts(tmp_path: Path):
    (tmp_path / "hello.py").write_text("print('hello')", encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_severity_is_block_post_portfolio_sweep(tmp_path: Path):
    # Promoted WARN -> BLOCK on 2026-04-19 after portfolio sweep
    # across 467 repos returned 0 real findings. Leaked credentials
    # MUST hard-block pushes. To demote back to WARN, add a fixture
    # here first that proves demotion was deliberate.
    rule = _rule()
    assert rule.severity == Severity.BLOCK


def test_aws_access_key_flagged(tmp_path: Path):
    (tmp_path / "deploy.py").write_text(
        'AWS_KEY = "AKIA' + 'Z' * 16 + '"', encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert "AWS access key" in verdicts[0].detail


def test_anthropic_key_flagged(tmp_path: Path):
    # Format: sk-ant-api01-<base64-like 95 chars>
    fake_body = "A1b2C3d4E5f6" * 8  # 96 chars, matches {32,}
    (tmp_path / "app.py").write_text(
        f'ANTHROPIC_KEY = "sk-ant-api03-{fake_body}"', encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert "Anthropic" in verdicts[0].detail


def test_github_pat_flagged(tmp_path: Path):
    (tmp_path / "ci.yml").write_text(
        "token: ghp_" + "a" * 36, encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert "GitHub token" in verdicts[0].detail


def test_private_key_header_flagged(tmp_path: Path):
    (tmp_path / "server.py").write_text(
        'KEY = """-----BEGIN RSA PRIVATE KEY-----\nMII...\n-----END..."""',
        encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert "Private key header" in verdicts[0].detail


def test_google_api_key_flagged(tmp_path: Path):
    (tmp_path / "app.js").write_text(
        'const K = "AIzaSy' + "A" * 33 + '";', encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert "Google API key" in verdicts[0].detail


def test_stripe_live_key_flagged(tmp_path: Path):
    (tmp_path / "pay.py").write_text(
        'STRIPE = "sk_live_' + "a" * 24 + '"', encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert "Stripe" in verdicts[0].detail


def test_example_near_match_suppressed(tmp_path: Path):
    # Documentation commonly mentions "example AKIA..." — don't flag.
    (tmp_path / "README.md").write_text(
        "# Setup\n\nYour key looks like: `example AKIA" + "Z" * 16 + "`",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_placeholder_near_match_suppressed(tmp_path: Path):
    (tmp_path / "config.sample.py").write_text(
        'API_KEY = "ghp_' + "a" * 36 + '"  # placeholder',
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_skip_file_marker_respected(tmp_path: Path):
    # Files with `sentinel:skip-file` in first 1KB are excluded by the
    # scanner before rules run. Verify the rule itself does the right
    # thing on a file that has genuine secrets but isn't skipped.
    # (The scanner-level skip is tested elsewhere.)
    (tmp_path / "secret.py").write_text(
        'KEY = "AKIA' + "Z" * 16 + '"', encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1


def test_fixtures_dir_excluded(tmp_path: Path):
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "bad.py").write_text(
        'K = "AKIA' + "Z" * 16 + '"', encoding="utf-8",
    )
    # fixtures/ is in SCAN_EXCLUDE_DIRS
    assert _rule().check(_ctx(tmp_path)) == []


def test_docs_dir_excluded(tmp_path: Path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "auth.md").write_text(
        "Key format: AKIA" + "Z" * 16, encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_large_file_skipped(tmp_path: Path):
    # Files over 2MB are skipped; real secrets live in small config.
    big = tmp_path / "huge.json"
    big.write_text("x" * 2_100_000 + "AKIA" + "Z" * 16, encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_binary_extensions_skipped(tmp_path: Path):
    # .jpg / .pdf / .exe are not in SCAN_EXTENSIONS
    (tmp_path / "image.png").write_bytes(b"PNG\x00AKIA" + b"Z" * 16)
    assert _rule().check(_ctx(tmp_path)) == []


def test_multiple_secrets_same_line_deduped(tmp_path: Path):
    # One verdict per (file, line, kind) — not one per literal match.
    (tmp_path / "bad.py").write_text(
        'A = "AKIA' + "Z" * 16 + '"; B = "AKIA' + "Y" * 16 + '"',
        encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    # Both are AWS-access-key on the same line; dedup key is
    # (file, line, name) — so exactly one verdict.
    assert len(verdicts) == 1


def test_line_number_reported(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "line1\nline2\nKEY='AKIA" + "Z" * 16 + "'\nline4",
        encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert verdicts[0].line == 3


def test_preview_redacts_middle(tmp_path: Path):
    # The emitted preview shows only the first 6 + last 4 chars, not
    # the full credential — avoids re-leaking it in the findings file.
    (tmp_path / "app.py").write_text(
        'KEY = "AKIA' + "Z" * 16 + '"', encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    # Preview should contain "..." since value is >12 chars
    assert "..." in verdicts[0].detail
    # Original key should NOT appear verbatim in detail
    assert "AKIA" + "Z" * 16 not in verdicts[0].detail
