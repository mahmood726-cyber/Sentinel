"""SHA-256 content manifest for Sentinel rule files.

Detects accidental drift (modified, missing, or extra rules), not tampering
by someone able to edit the repo and regenerate the manifest. No key is
needed. Legacy manifests' signature fields are ignored.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import NamedTuple, Optional


# Default location of the manifest, relative to a Sentinel repo root.
DEFAULT_MANIFEST_REL = "rules-manifest.json"


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

    Legacy signature fields are ignored."""
    doc = load_manifest_full(manifest_path)
    return None if doc is None else doc.rules


class ManifestDoc(NamedTuple):
    """A parsed content manifest."""
    version: int
    rules: dict[str, str]
    note: str


def load_manifest_full(manifest_path: Path) -> Optional[ManifestDoc]:
    """Load the manifest, ignoring any legacy signature field.

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

    return ManifestDoc(version=version, rules=rules, note=note)


def write_manifest(
    manifest_path: Path,
    rules: dict[str, str],
    note: str = "",
) -> None:
    """Write a plain SHA-256 manifest with deterministic rule ordering."""
    sorted_rules = dict(sorted(rules.items()))
    payload: dict = {
        "version": 1,
        "note": note or (
            "sha256 of every Sentinel rule file. Drift here = a rule "
            "file was added/removed/modified outside the normal commit "
            "flow. Regenerate via `python -m sentinel verify-rules --update`."
        ),
        "rules": sorted_rules,
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
