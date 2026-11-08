"""Tests for rule_integrity module + verify-rules CLI command.

v6 benchmark gap #2: protect Sentinel's own rule files from
accidental drift by comparing rule-file hashes against the manifest.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from sentinel.registry.rule_integrity import (
    compare,
    compute_manifest,
    load_manifest,
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


@pytest.mark.parametrize("checkout", [b"a: 1\nb: 2\n", b"a: 1\r\nb: 2\r\n", b"a: 1\r\nb: 2\n"])
def test_compute_manifest_ignores_line_endings(tmp_path: Path, checkout: bytes):
    # A blob with mixed endings checks out as different bytes under
    # core.autocrlf=true, so a raw-byte hash reported drift on a clean
    # Windows checkout (F:\Sentinel, 2026-11-08). Same text, same hash.
    reference = tmp_path / "ref"
    (reference / "yaml").mkdir(parents=True)
    (reference / "yaml" / "r.yaml").write_bytes(b"a: 1\nb: 2\n")
    other = tmp_path / "other"
    (other / "yaml").mkdir(parents=True)
    (other / "yaml" / "r.yaml").write_bytes(checkout)
    assert compute_manifest(other) == compute_manifest(reference)


def test_compute_manifest_still_sees_edits_after_normalising(tmp_path: Path):
    a = tmp_path / "a"
    (a / "yaml").mkdir(parents=True)
    (a / "yaml" / "r.yaml").write_bytes(b"a: 1\r\nb: 2\r\n")
    b = tmp_path / "b"
    (b / "yaml").mkdir(parents=True)
    (b / "yaml" / "r.yaml").write_bytes(b"a: 1\r\nb: 3\r\n")
    assert compute_manifest(a) != compute_manifest(b)


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



@pytest.mark.parametrize("signature", [None, {}, "legacy", {"algo": "HMAC-SHA256", "value": "old"}])
@pytest.mark.parametrize("change", ["none", "modified", "added", "removed"])
def test_legacy_manifest_content_check(tmp_path, monkeypatch, signature, change):
    manifest = tmp_path / "rules-manifest.json"
    rules = compute_manifest(SENTINEL_ROOT / "sentinel" / "rules")
    name = next(iter(rules))
    if change == "modified":
        rules[name] = "0" * 64
    elif change == "added":
        del rules[name]
    elif change == "removed":
        name = "plugins/missing.py"
        rules[name] = "0" * 64
    manifest.write_text(json.dumps({"version": 2, "rules": rules, "signature": signature}), encoding="utf-8")
    monkeypatch.setenv("SENTINEL_MANIFEST_HMAC_KEY", "irrelevant")
    res = _run_cli("--manifest", str(manifest), "--json")
    assert res.returncode == (0 if change == "none" else 1)
    data = json.loads(res.stdout)
    assert data["status"] == ("ok" if change == "none" else "drift")
    if change != "none":
        assert data[change] == [name]
    assert "signature" not in data


@pytest.mark.parametrize("key_value", [None, "", "   ", "unused"])
@pytest.mark.parametrize("json_output", [False, True])
def test_update_plain_manifest_env(tmp_path, monkeypatch, key_value, json_output):
    if key_value is None:
        monkeypatch.delenv("SENTINEL_MANIFEST_HMAC_KEY", raising=False)
    else:
        monkeypatch.setenv("SENTINEL_MANIFEST_HMAC_KEY", key_value)
    key_file = tmp_path / "legacy-key"
    key_file.write_text("unused", encoding="utf-8")
    monkeypatch.setenv("SENTINEL_MANIFEST_KEY_FILE", str(key_file))
    manifest = tmp_path / "rules-manifest.json"
    args = ("--json",) if json_output else ()
    res = _run_cli("--update", "--manifest", str(manifest), *args)
    assert res.returncode == 0
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    assert set(raw) == {"version", "note", "rules"}
    assert raw["version"] == 1
    assert raw["rules"] == compute_manifest(SENTINEL_ROOT / "sentinel" / "rules")
    assert "key" not in (res.stdout + res.stderr).lower()
    assert _run_cli("--manifest", str(manifest)).returncode == 0
