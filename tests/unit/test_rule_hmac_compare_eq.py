"""Tests for P0-hmac-compare-eq.

Fires on `==` / `!=` comparing crypto-sensitive identifiers (anything
whose name contains hmac / signature / digest / mac_value / auth_tag /
auth_code / _mac / _sig / _tag). Past incident: lessons.md
"Constant-time comparison: always hmac.compare_digest, never ==".
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "hmac_compare_eq.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def test_severity_is_block(tmp_path):
    """Block — failure is silent (functional tests pass; vulnerability only
    appears under adversarial timing measurement)."""
    assert _rule().severity == Severity.BLOCK


def test_fires_on_hmac_equality(tmp_path):
    (tmp_path / "bad.py").write_text(
        "if hmac_value == expected:\n    pass\n", encoding="utf-8"
    )
    assert len(_rule().check(_ctx(tmp_path))) == 1


def test_fires_on_signature_inequality(tmp_path):
    (tmp_path / "bad.py").write_text(
        "if signature != trusted_sig:\n    raise\n", encoding="utf-8"
    )
    assert len(_rule().check(_ctx(tmp_path))) == 1


def test_fires_on_dotted_attribute(tmp_path):
    """Past-incident shape: `bundle.signature == stored_sig`."""
    (tmp_path / "bad.py").write_text(
        "ok = bundle.signature == stored_sig\n", encoding="utf-8"
    )
    assert len(_rule().check(_ctx(tmp_path))) == 1


def test_quiet_on_compare_digest(tmp_path):
    (tmp_path / "good.py").write_text(
        "if hmac.compare_digest(sig, expected):\n    pass\n", encoding="utf-8"
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_non_crypto_identifiers(tmp_path):
    (tmp_path / "good.py").write_text(
        "if name == other_name:\n    pass\n", encoding="utf-8"
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_skip_line_marker_honored(tmp_path):
    """Per-line skip marker (sentinel:skip-line) is recognised — operator
    can override on a per-test-assertion basis when the comparison is
    provably against a literal or non-secret value."""
    (tmp_path / "test_foo.py").write_text(
        "def test_x():\n"
        "    # sentinel:skip-line P0-hmac-compare-eq\n"
        "    assert result.signature == ''\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_statistical_significance_identifiers(tmp_path):
    """Regression for 2026-05-27 FP: MetaReproducer's
    `same_sig = ref_sig == repro_sig` was firing because the bare `_sig`
    substring matched `significance`. The suffix-anchored rule rejects
    these stats identifiers (no actual signature byte-equality involved)."""
    (tmp_path / "good.py").write_text(
        "same_sig = ref_sig == repro_sig\n"
        "agree = hta_significant == r_significant\n"
        "tag_count = len(tags) == len(other_tags)\n"
        "is_macro = macroaverage == microaverage\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_bare_sig_shorthand(tmp_path):
    """`_sig` / `_tag` / `_mac` suffix forms are NOT flagged because they
    collide with `significance` / `tags` / `macroaverage`. Operators who
    write crypto with the shorthand should also name `signature` or
    `hmac` somewhere in the comparison, or add a skip-line marker."""
    (tmp_path / "good.py").write_text(
        "if bundle_sig == expected_sig:\n    accept()\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_strings_and_comments(tmp_path):
    """The bad pattern in docstrings / comments / string literals must
    not trigger the rule."""
    (tmp_path / "good.py").write_text(
        '"""Example of the bad form: signature == expected."""\n'
        "# also bad: hmac_value == thing\n"
        'msg = "if signature == expected: ..."\n'
        "x = 1\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []
