"""Rule-integrity verification — protect Sentinel's own rule files from drift.

v6 benchmark gap #2 (2026-04-29). Sentinel rules ARE the rule of law for
this portfolio. An attacker (insider, or via compromised dev box) who
edits a rule's regex to weaken it bypasses Sentinel forever — and there
is no automated check that rules match a known-good state.

Defense: a `rules-manifest.json` at the Sentinel repo root that stores
sha256 hashes of every rule file (YAML rules + plugin Python rules).
On `sentinel verify-rules`, we recompute the hashes and exit nonzero
if anything diverged — added rule, removed rule, or modified content.

Hashing vs signing (updated 2026-07-11, benchmark item #5 / ★3):
  The original design hashed-only and leaned on git history as the audit
  log. That defends against a careless edit that lands in a diff, but NOT
  against an attacker who edits a rule AND regenerates the manifest hash in
  the same commit — the hash-check then passes and the weakened rule ships.
  A keyed signature closes that: regenerating the hash is not enough; the
  attacker also needs the HMAC key, which never lives in the repo. Git
  tamper-evidence and the keyed signature are complementary, not redundant.

  The key is read from the ``SENTINEL_MANIFEST_HMAC_KEY`` env var, or from a
  gitignored key file (``SENTINEL_MANIFEST_KEY_FILE``, default
  ``<repo>/.sentinel-manifest-key``). It is NEVER hardcoded and NEVER
  committed. Signing degrades gracefully: with no key available, verify
  still checks hashes (legacy behaviour, no regression) and reports the
  signature as UNVERIFIED; ``--require-signature`` turns that into a
  hard, fail-closed failure for CI / Overmind.

Why this is a manual verify command, not an auto-firing rule:
  An auto-firing rule that checks rule integrity is recursive — if the
  attacker modifies the integrity rule, the check is bypassed. Keeping
  it as a separate command (run by Overmind nightly + CI) breaks the
  recursion.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from enum import Enum
from pathlib import Path
from typing import NamedTuple, Optional


# Default location of the manifest, relative to a Sentinel repo root.
DEFAULT_MANIFEST_REL = "rules-manifest.json"

# Env var holding the raw HMAC key (utf-8 text). Takes precedence over the
# key file. NEVER hardcode a key; NEVER commit one.
SIGNING_KEY_ENV = "SENTINEL_MANIFEST_HMAC_KEY"
# Env var pointing at a gitignored key file. Falls back to KEY_FILE_DEFAULT
# (relative to the Sentinel repo root) when unset.
KEY_FILE_ENV = "SENTINEL_MANIFEST_KEY_FILE"
KEY_FILE_DEFAULT = ".sentinel-manifest-key"

# HMAC construction identifier stored in the manifest so verifiers know
# which algorithm produced `signature`.
SIGNATURE_ALGO = "HMAC-SHA256"
MANIFEST_VERSION = 2  # v1 = unsigned (hash-only); v2 = adds signature block


class IntegrityReport(NamedTuple):
    """Result of comparing current rule files against a saved manifest."""
    added: list[str]       # rule file present now, not in manifest
    removed: list[str]     # rule file in manifest, not present now
    modified: list[str]    # rule file present in both with different hash
    in_sync: list[str]     # rule file present in both with same hash

    @property
    def has_drift(self) -> bool:
        return bool(self.added or self.removed or self.modified)

    def summary(self) -> str:
        if not self.has_drift:
            return f"rule integrity OK ({len(self.in_sync)} rules in sync)"
        lines = [
            f"rule integrity DRIFT: +{len(self.added)} -{len(self.removed)} "
            f"~{len(self.modified)} (in-sync: {len(self.in_sync)})",
        ]
        for rel in sorted(self.added):
            lines.append(f"  + {rel}  (NEW; not in manifest)")
        for rel in sorted(self.removed):
            lines.append(f"  - {rel}  (REMOVED; manifest has it but file missing)")
        for rel in sorted(self.modified):
            lines.append(f"  ~ {rel}  (MODIFIED; hash differs)")
        return "\n".join(lines)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _iter_rule_files(rules_root: Path):
    """Yield (relative_path, absolute_path) for every YAML rule + plugin
    Python rule under rules_root. Excludes __init__.py and __pycache__."""
    yaml_dir = rules_root / "yaml"
    if yaml_dir.is_dir():
        for p in sorted(yaml_dir.glob("*.yaml")):
            yield (f"yaml/{p.name}", p)
    plugins_dir = rules_root / "plugins"
    if plugins_dir.is_dir():
        for p in sorted(plugins_dir.glob("*.py")):
            if p.stem == "__init__":
                continue
            yield (f"plugins/{p.name}", p)


def compute_manifest(rules_root: Path) -> dict[str, str]:
    """Return {relative_path: sha256_hex} for every rule file under rules_root.

    Stable ordering — relative paths under yaml/ and plugins/ — so the
    manifest JSON is byte-identical across runs that haven't changed
    rules. This makes git diffs surface real drift, not noise."""
    manifest: dict[str, str] = {}
    for rel, abs_path in _iter_rule_files(rules_root):
        try:
            content = abs_path.read_bytes()
        except OSError:
            continue
        manifest[rel] = _sha256_bytes(content)
    return manifest


def load_manifest(manifest_path: Path) -> dict[str, str] | None:
    """Load the rules subdict of a previously-written rules-manifest.json.
    Returns None if the file is missing or unparseable — caller MUST
    treat None as "no baseline; cannot verify" and decide policy.

    Backward-compatible: returns only the {rel_path: sha256} mapping,
    unchanged from the v1 hash-only design. Callers that also need the
    signature block use `load_manifest_full`."""
    doc = load_manifest_full(manifest_path)
    return None if doc is None else doc.rules


# ── keyed signing (v2) ───────────────────────────────────────────────


class SignatureStatus(Enum):
    """Outcome of verifying a manifest's HMAC signature."""
    OK = "ok"                     # signature present, key present, matches
    MISMATCH = "mismatch"         # signature present, key present, does NOT match — TAMPER
    NO_SIGNATURE = "no_signature"  # manifest carries no signature block (legacy v1)
    NO_KEY = "no_key"             # signature present but no key available to verify


class ManifestDoc(NamedTuple):
    """A parsed manifest: rule hashes plus the optional signature block."""
    version: int
    rules: dict[str, str]
    note: str
    signature: Optional[str]   # hex HMAC, or None if unsigned
    algo: Optional[str]        # e.g. "HMAC-SHA256", or None if unsigned


def canonical_signing_bytes(version: int, rules: dict[str, str]) -> bytes:
    """Deterministic byte string the HMAC is computed over.

    Binds BOTH the manifest version and the exact set of rule hashes, with
    sorted keys and compact separators so the bytes are identical across
    machines/Python versions. The `note` and the `signature` field itself
    are deliberately excluded — editing the human note must not invalidate
    the signature, and a MAC cannot cover itself."""
    payload = {
        "version": int(version),
        "rules": dict(sorted(rules.items())),
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def compute_signature(version: int, rules: dict[str, str], key: bytes) -> str:
    """Return the hex HMAC-SHA256 of the canonical manifest bytes under `key`."""
    return hmac.new(
        key, canonical_signing_bytes(version, rules), hashlib.sha256
    ).hexdigest()


def verify_signature(
    version: int, rules: dict[str, str], signature: str, key: bytes
) -> bool:
    """Constant-time check that `signature` is a valid HMAC of the manifest.

    Uses hmac.compare_digest (never `==`) so a partial-match attacker gains
    no timing signal — same rule Sentinel enforces via P0-hmac-compare-eq."""
    expected = compute_signature(version, rules, key)
    return hmac.compare_digest(expected, str(signature))


def load_signing_key(repo_root: Optional[Path] = None) -> Optional[bytes]:
    """Resolve the HMAC key, or None if unavailable.

    Resolution order (first hit wins):
      1. ``SENTINEL_MANIFEST_HMAC_KEY`` env var (raw utf-8 text).
      2. Key file at ``SENTINEL_MANIFEST_KEY_FILE`` (env) or
         ``<repo_root>/.sentinel-manifest-key`` (default).

    Returns None when neither is present — callers decide whether that is a
    soft (verify hashes only) or hard (`--require-signature`) failure. A
    blank/whitespace-only key is treated as absent (never silent-default to
    an empty key)."""
    env_key = os.environ.get(SIGNING_KEY_ENV)
    if env_key and env_key.strip():
        return env_key.encode("utf-8")

    key_file_env = os.environ.get(KEY_FILE_ENV)
    if key_file_env:
        key_path = Path(key_file_env)
    elif repo_root is not None:
        key_path = repo_root / KEY_FILE_DEFAULT
    else:
        return None
    try:
        raw = key_path.read_bytes()
    except OSError:
        return None
    if not raw.strip():
        return None
    return raw.strip()


def check_signature(
    doc: ManifestDoc, key: Optional[bytes]
) -> SignatureStatus:
    """Adjudicate a loaded manifest's signature against an (optional) key."""
    if not doc.signature:
        return SignatureStatus.NO_SIGNATURE
    if key is None:
        return SignatureStatus.NO_KEY
    ok = verify_signature(doc.version, doc.rules, doc.signature, key)
    return SignatureStatus.OK if ok else SignatureStatus.MISMATCH


def load_manifest_full(manifest_path: Path) -> Optional[ManifestDoc]:
    """Load the full manifest (rule hashes + signature block).

    Returns None on missing/unparseable/wrong-shape files — same
    fail-closed contract as `load_manifest`. Rule entries with non-string
    keys/values or non-64-char hashes are filtered out (matching v1)."""
    if not manifest_path.is_file():
        return None
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    rules_raw = data.get("rules")
    if not isinstance(rules_raw, dict):
        return None
    rules: dict[str, str] = {}
    for k, v in rules_raw.items():
        if isinstance(k, str) and isinstance(v, str) and len(v) == 64:
            rules[k] = v

    version = data.get("version")
    version = version if isinstance(version, int) else 1
    note = data.get("note")
    note = note if isinstance(note, str) else ""

    signature: Optional[str] = None
    algo: Optional[str] = None
    sig_block = data.get("signature")
    if isinstance(sig_block, dict):
        val = sig_block.get("value")
        alg = sig_block.get("algo")
        if isinstance(val, str) and val:
            signature = val
        if isinstance(alg, str) and alg:
            algo = alg

    return ManifestDoc(
        version=version, rules=rules, note=note, signature=signature, algo=algo
    )


def write_manifest(
    manifest_path: Path,
    rules: dict[str, str],
    note: str = "",
    key: Optional[bytes] = None,
) -> None:
    """Write a manifest atomically. The wrapper dict has a `version` field
    and a `note` for auditability — the rules subdict is what verify
    compares against.

    When `key` is provided, an HMAC-SHA256 `signature` block over the
    canonical (version, rules) bytes is embedded, and the version is bumped
    to MANIFEST_VERSION (2). When `key` is None, an unsigned v1 manifest is
    written — byte-identical to the historical format, so existing tests and
    tooling are unaffected."""
    signed = key is not None
    version = MANIFEST_VERSION if signed else 1
    sorted_rules = dict(sorted(rules.items()))
    payload: dict = {
        "version": version,
        "note": note or (
            "sha256 of every Sentinel rule file. Drift here = a rule "
            "file was added/removed/modified outside the normal commit "
            "flow. Regenerate via `python -m sentinel verify-rules --update`."
        ),
        "rules": sorted_rules,
    }
    if signed:
        payload["signature"] = {
            "algo": SIGNATURE_ALGO,
            "value": compute_signature(version, sorted_rules, key),  # type: ignore[arg-type]
            "note": (
                "HMAC-SHA256 over canonical (version, rules) bytes. Key from "
                f"${SIGNING_KEY_ENV} or the gitignored key file. Verify with "
                "`python -m sentinel verify-rules --require-signature`."
            ),
        }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(payload, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def compare(current: dict[str, str], saved: dict[str, str]) -> IntegrityReport:
    """Compute the drift report between two manifests."""
    current_keys = set(current)
    saved_keys = set(saved)
    added = sorted(current_keys - saved_keys)
    removed = sorted(saved_keys - current_keys)
    common = current_keys & saved_keys
    modified = sorted(k for k in common if current[k] != saved[k])
    in_sync = sorted(k for k in common if current[k] == saved[k])
    return IntegrityReport(
        added=added,
        removed=removed,
        modified=modified,
        in_sync=in_sync,
    )
