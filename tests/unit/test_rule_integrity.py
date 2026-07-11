"""Tests for rule_integrity module + verify-rules CLI command.

v6 benchmark gap #2: protect Sentinel's own rule files from
out-of-band tampering by hashing rules-manifest.json and comparing on
demand.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import os

import pytest

from sentinel.registry.rule_integrity import (
    KEY_FILE_ENV,
    SIGNING_KEY_ENV,
    SignatureStatus,
    canonical_signing_bytes,
    check_signature,
    compare,
    compute_manifest,
    compute_signature,
    load_manifest,
    load_manifest_full,
    load_signing_key,
    verify_signature,
    write_manifest,
)

SENTINEL_ROOT = Path(__file__).parent.parent.parent


# ── compute_manifest ─────────────────────────────────────────────────


def test_compute_manifest_includes_yaml_and_plugins(tmp_path: Path):
    rules = tmp_path / "rules"
    (rules / "yaml").mkdir(parents=True)
    (rules / "plugins").mkdir(parents=True)
    (rules / "yaml" / "P0-test.yaml").write_text("rule: x\n", encoding="utf-8")
    (rules / "plugins" / "test_rule.py").write_text("def check(): pass\n",
                                                     encoding="utf-8")
    (rules / "plugins" / "__init__.py").write_text("", encoding="utf-8")

    m = compute_manifest(rules)
    assert "yaml/P0-test.yaml" in m
    assert "plugins/test_rule.py" in m
    # __init__ is excluded
    assert "plugins/__init__.py" not in m
    # Each value is a 64-char hex sha256
    for v in m.values():
        assert len(v) == 64
        int(v, 16)  # must be hex


def test_compute_manifest_stable_across_runs(tmp_path: Path):
    rules = tmp_path / "rules"
    (rules / "yaml").mkdir(parents=True)
    (rules / "yaml" / "rule.yaml").write_text("data\n", encoding="utf-8")
    m1 = compute_manifest(rules)
    m2 = compute_manifest(rules)
    assert m1 == m2


def test_compute_manifest_changes_on_content_edit(tmp_path: Path):
    rules = tmp_path / "rules"
    (rules / "yaml").mkdir(parents=True)
    f = rules / "yaml" / "rule.yaml"
    f.write_text("v1\n", encoding="utf-8")
    m1 = compute_manifest(rules)
    f.write_text("v2\n", encoding="utf-8")
    m2 = compute_manifest(rules)
    assert m1 != m2
    assert m1["yaml/rule.yaml"] != m2["yaml/rule.yaml"]


def test_compute_manifest_empty_rules_root(tmp_path: Path):
    """No yaml/ or plugins/ dir under rules_root → empty manifest, no crash."""
    rules = tmp_path / "rules"
    rules.mkdir()
    m = compute_manifest(rules)
    assert m == {}


# ── round-trip write/load ────────────────────────────────────────────


def test_write_and_load_round_trip(tmp_path: Path):
    rules = {"yaml/a.yaml": "a" * 64, "plugins/b.py": "b" * 64}
    write_manifest(tmp_path / "rules-manifest.json", rules, note="test")
    loaded = load_manifest(tmp_path / "rules-manifest.json")
    assert loaded == rules


def test_load_manifest_missing_returns_none(tmp_path: Path):
    assert load_manifest(tmp_path / "no-such.json") is None


def test_load_manifest_corrupt_returns_none(tmp_path: Path):
    p = tmp_path / "broken.json"
    p.write_text("{ not valid", encoding="utf-8")
    assert load_manifest(p) is None


def test_load_manifest_wrong_shape_returns_none(tmp_path: Path):
    """JSON parses but isn't the expected {"rules": {...}} shape."""
    p = tmp_path / "wrong.json"
    p.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    assert load_manifest(p) is None


def test_load_manifest_filters_invalid_entries(tmp_path: Path):
    """Rule entries with non-string keys/values or wrong-length hashes
    are filtered out, not crashed on."""
    p = tmp_path / "mixed.json"
    p.write_text(json.dumps({
        "version": 1,
        "rules": {
            "good.yaml": "a" * 64,
            "bad.yaml": "short",          # wrong length → filtered
            "weird.yaml": 123,            # wrong type → filtered
        }
    }), encoding="utf-8")
    loaded = load_manifest(p)
    assert loaded == {"good.yaml": "a" * 64}


# ── compare / IntegrityReport ────────────────────────────────────────


def test_compare_in_sync():
    r = compare({"a": "h1", "b": "h2"}, {"a": "h1", "b": "h2"})
    assert not r.has_drift
    assert r.in_sync == ["a", "b"]
    assert r.added == []
    assert r.removed == []
    assert r.modified == []


def test_compare_added_file():
    r = compare({"a": "h1", "new.yaml": "h-new"}, {"a": "h1"})
    assert r.has_drift
    assert r.added == ["new.yaml"]


def test_compare_removed_file():
    r = compare({"a": "h1"}, {"a": "h1", "gone.yaml": "h-gone"})
    assert r.has_drift
    assert r.removed == ["gone.yaml"]


def test_compare_modified_file():
    r = compare({"a": "h1"}, {"a": "h0"})
    assert r.has_drift
    assert r.modified == ["a"]


def test_compare_summary_distinguishes_categories():
    r = compare(
        {"a": "h1", "new.yaml": "h-new", "modded": "h2"},
        {"a": "h1", "removed.yaml": "h-r", "modded": "h-old"},
    )
    s = r.summary()
    assert "+1" in s
    assert "-1" in s
    assert "~1" in s
    assert "new.yaml" in s
    assert "removed.yaml" in s
    assert "modded" in s


# ── CLI smoke test ───────────────────────────────────────────────────


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "sentinel", "verify-rules", *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(SENTINEL_ROOT),
    )


def test_cli_reports_no_manifest_when_missing(tmp_path: Path):
    res = _run_cli(
        "--manifest", str(tmp_path / "no-such.json"),
    )
    assert res.returncode == 2
    assert "no manifest" in (res.stdout + res.stderr).lower()


def test_cli_update_creates_manifest_then_verifies_clean(tmp_path: Path):
    manifest = tmp_path / "rules-manifest.json"
    # Create
    res1 = _run_cli("--update", "--manifest", str(manifest))
    assert res1.returncode == 0
    assert manifest.is_file()
    # Verify clean
    res2 = _run_cli("--manifest", str(manifest))
    assert res2.returncode == 0
    assert "OK" in res2.stdout


def test_cli_json_output_shape(tmp_path: Path):
    manifest = tmp_path / "rules-manifest.json"
    _run_cli("--update", "--manifest", str(manifest))
    res = _run_cli("--manifest", str(manifest), "--json")
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["status"] == "ok"
    assert "added" in data
    assert "removed" in data
    assert "modified" in data
    assert isinstance(data["in_sync_count"], int)


# ── keyed signing (v2) ───────────────────────────────────────────────
#
# Signature layer added 2026-07-11 (benchmark item #5 / ★3). These tests
# NEVER touch the real repo key — they use throwaway keys in tmp_path.


TEST_KEY = b"test-key-not-the-real-one-0123456789abcdef"
OTHER_KEY = b"a-different-key-ffffffffffffffffffffffffff"


@pytest.fixture(autouse=True)
def _isolate_signing_env(monkeypatch):
    """Ensure no ambient key leaks in from the developer's environment."""
    monkeypatch.delenv(SIGNING_KEY_ENV, raising=False)
    monkeypatch.delenv(KEY_FILE_ENV, raising=False)


def test_canonical_bytes_are_deterministic_and_order_independent():
    a = canonical_signing_bytes(2, {"b": "2" * 64, "a": "1" * 64})
    b = canonical_signing_bytes(2, {"a": "1" * 64, "b": "2" * 64})
    assert a == b  # sorted keys → key-order irrelevant


def test_canonical_bytes_change_with_version_and_rules():
    base = canonical_signing_bytes(2, {"a": "1" * 64})
    assert canonical_signing_bytes(1, {"a": "1" * 64}) != base
    assert canonical_signing_bytes(2, {"a": "2" * 64}) != base


def test_sign_then_verify_ok():
    rules = {"a": "1" * 64, "b": "2" * 64}
    sig = compute_signature(2, rules, TEST_KEY)
    assert verify_signature(2, rules, sig, TEST_KEY) is True


def test_verify_fails_with_wrong_key():
    rules = {"a": "1" * 64}
    sig = compute_signature(2, rules, TEST_KEY)
    assert verify_signature(2, rules, sig, OTHER_KEY) is False


def test_verify_fails_when_rules_edited_after_signing():
    """The core guarantee: editing a rule hash after signing invalidates
    the signature even though the (recomputed) hash-check would pass."""
    rules = {"a": "1" * 64}
    sig = compute_signature(2, rules, TEST_KEY)
    tampered = {"a": "9" * 64}
    assert verify_signature(2, tampered, sig, TEST_KEY) is False


def test_write_signed_manifest_embeds_signature(tmp_path: Path):
    manifest = tmp_path / "rules-manifest.json"
    rules = {"plugins/x.py": "c" * 64}
    write_manifest(manifest, rules, key=TEST_KEY)
    doc = load_manifest_full(manifest)
    assert doc is not None
    assert doc.version == 2
    assert doc.algo == "HMAC-SHA256"
    assert doc.signature is not None
    assert check_signature(doc, TEST_KEY) == SignatureStatus.OK


def test_write_unsigned_manifest_is_legacy_v1(tmp_path: Path):
    """No key → byte-compatible v1 output, no signature block."""
    manifest = tmp_path / "rules-manifest.json"
    write_manifest(manifest, {"a": "1" * 64})
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    assert raw["version"] == 1
    assert "signature" not in raw
    doc = load_manifest_full(manifest)
    assert check_signature(doc, TEST_KEY) == SignatureStatus.NO_SIGNATURE


def test_editing_note_does_not_break_signature(tmp_path: Path):
    """The note is excluded from the signed payload by design."""
    manifest = tmp_path / "rules-manifest.json"
    rules = {"a": "1" * 64}
    write_manifest(manifest, rules, note="original", key=TEST_KEY)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["note"] = "edited by a human, harmlessly"
    manifest.write_text(json.dumps(data, indent=2), encoding="utf-8")
    doc = load_manifest_full(manifest)
    assert check_signature(doc, TEST_KEY) == SignatureStatus.OK


def test_tampered_rule_hash_yields_mismatch(tmp_path: Path):
    manifest = tmp_path / "rules-manifest.json"
    write_manifest(manifest, {"a": "1" * 64}, key=TEST_KEY)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["rules"]["a"] = "2" * 64  # flip hash, keep old signature
    manifest.write_text(json.dumps(data, indent=2), encoding="utf-8")
    doc = load_manifest_full(manifest)
    assert check_signature(doc, TEST_KEY) == SignatureStatus.MISMATCH


def test_check_signature_no_key(tmp_path: Path):
    manifest = tmp_path / "rules-manifest.json"
    write_manifest(manifest, {"a": "1" * 64}, key=TEST_KEY)
    doc = load_manifest_full(manifest)
    assert check_signature(doc, None) == SignatureStatus.NO_KEY


# ── key resolution ───────────────────────────────────────────────────


def test_load_signing_key_from_env(monkeypatch):
    monkeypatch.setenv(SIGNING_KEY_ENV, "supersecret")
    assert load_signing_key() == b"supersecret"


def test_load_signing_key_blank_env_is_absent(monkeypatch):
    monkeypatch.setenv(SIGNING_KEY_ENV, "   ")
    assert load_signing_key() is None


def test_load_signing_key_from_file(monkeypatch, tmp_path: Path):
    kf = tmp_path / "key"
    kf.write_bytes(b"filekey123\n")
    monkeypatch.setenv(KEY_FILE_ENV, str(kf))
    assert load_signing_key() == b"filekey123"  # trailing newline stripped


def test_load_signing_key_env_beats_file(monkeypatch, tmp_path: Path):
    kf = tmp_path / "key"
    kf.write_bytes(b"filekey")
    monkeypatch.setenv(KEY_FILE_ENV, str(kf))
    monkeypatch.setenv(SIGNING_KEY_ENV, "envkey")
    assert load_signing_key() == b"envkey"


def test_load_signing_key_default_repo_file(monkeypatch, tmp_path: Path):
    (tmp_path / ".sentinel-manifest-key").write_bytes(b"repokey")
    assert load_signing_key(tmp_path) == b"repokey"


def test_load_signing_key_absent_returns_none(tmp_path: Path):
    assert load_signing_key(tmp_path) is None


# ── CLI: signature behaviour matrix ──────────────────────────────────


def _run_cli_env(env_extra: dict, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.pop(SIGNING_KEY_ENV, None)
    env.pop(KEY_FILE_ENV, None)
    env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "sentinel", "verify-rules", *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(SENTINEL_ROOT), env=env,
    )


def test_cli_update_signs_when_key_present(tmp_path: Path):
    manifest = tmp_path / "rules-manifest.json"
    res = _run_cli_env({SIGNING_KEY_ENV: "k"}, "--update", "--manifest", str(manifest))
    assert res.returncode == 0
    assert "SIGNED" in res.stdout
    doc = load_manifest_full(manifest)
    assert doc.signature is not None
    assert check_signature(doc, b"k") == SignatureStatus.OK


def test_cli_update_unsigned_without_key(tmp_path: Path):
    manifest = tmp_path / "rules-manifest.json"
    res = _run_cli_env({KEY_FILE_ENV: str(tmp_path / "nope")}, "--update", "--manifest", str(manifest))
    assert res.returncode == 0
    assert "UNSIGNED" in res.stdout
    assert load_manifest_full(manifest).signature is None


def test_cli_require_signature_refuses_unsigned_update(tmp_path: Path):
    manifest = tmp_path / "rules-manifest.json"
    res = _run_cli_env(
        {KEY_FILE_ENV: str(tmp_path / "nope")},
        "--update", "--require-signature", "--manifest", str(manifest),
    )
    assert res.returncode == 2
    assert not manifest.is_file()


def test_cli_require_signature_passes_signed(tmp_path: Path):
    manifest = tmp_path / "rules-manifest.json"
    _run_cli_env({SIGNING_KEY_ENV: "k"}, "--update", "--manifest", str(manifest))
    res = _run_cli_env({SIGNING_KEY_ENV: "k"}, "--require-signature", "--manifest", str(manifest))
    assert res.returncode == 0
    assert "signature OK" in res.stdout


def test_cli_require_signature_fails_wrong_key(tmp_path: Path):
    manifest = tmp_path / "rules-manifest.json"
    _run_cli_env({SIGNING_KEY_ENV: "k"}, "--update", "--manifest", str(manifest))
    res = _run_cli_env({SIGNING_KEY_ENV: "WRONG"}, "--require-signature", "--manifest", str(manifest))
    assert res.returncode == 1
    assert "MISMATCH" in res.stdout


def test_cli_signed_manifest_verifies_hashes_without_key(tmp_path: Path):
    """No-regression: a signed manifest with no key still passes the hash
    check (soft), only reporting the signature as unverified."""
    manifest = tmp_path / "rules-manifest.json"
    _run_cli_env({SIGNING_KEY_ENV: "k"}, "--update", "--manifest", str(manifest))
    res = _run_cli_env({KEY_FILE_ENV: str(tmp_path / "nope")}, "--manifest", str(manifest))
    assert res.returncode == 0
    assert "UNVERIFIED" in res.stdout


def test_cli_json_reports_signature_field(tmp_path: Path):
    manifest = tmp_path / "rules-manifest.json"
    _run_cli_env({SIGNING_KEY_ENV: "k"}, "--update", "--manifest", str(manifest))
    res = _run_cli_env({SIGNING_KEY_ENV: "k"}, "--manifest", str(manifest), "--json")
    data = json.loads(res.stdout)
    assert data["signature"] == "ok"
    assert data["signature_algo"] == "HMAC-SHA256"
    assert data["signature_failed"] is False
