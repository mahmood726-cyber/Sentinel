"""`sentinel verify-rules` — check rule files against rules-manifest.json.

Run modes:
  python -m sentinel verify-rules              # check hashes (+ signature if key present)
  python -m sentinel verify-rules --require-signature   # CI/Overmind: fail closed unless signature verifies
  python -m sentinel verify-rules --update     # regenerate manifest (signs if a key is available)
  python -m sentinel verify-rules --json       # machine-readable output

v6 benchmark gap #2 (2026-04-29). Standalone CLI command, NOT a
Sentinel rule plugin — recursive dependency (a rule that checks rules
can be modified to bypass itself). Keeping as a separate verify
command lets Overmind nightly invoke it independently as a witness.

Signature layer added 2026-07-11 (benchmark item #5 / ★3): a keyed
HMAC-SHA256 over the manifest so regenerating the hash is not enough to
ship a weakened rule — the attacker also needs the key, which never
lives in the repo. Behaviour matrix for check mode:

  manifest signed? | key present? | --require-signature | result
  -----------------+--------------+---------------------+----------------------
  no  (legacy v1)  |     any      |        no            | hashes only  (exit=drift)
  no  (legacy v1)  |     any      |        yes           | FAIL closed (exit 1)
  yes              |     no       |        no            | hashes only + WARN unverified
  yes              |     no       |        yes           | FAIL closed (exit 1)
  yes              |     yes,ok   |        any           | hashes + signature OK
  yes              |     yes,bad  |        any           | FAIL closed (exit 1) TAMPER

Default (no --require-signature) never regresses the legacy behaviour:
a missing key still lets the hash check run. --require-signature is the
hard gate CI and the Overmind nightly should use.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from typing import Any

from sentinel.registry.rule_integrity import (
    DEFAULT_MANIFEST_REL,
    SIGNING_KEY_ENV,
    SignatureStatus,
    check_signature,
    compare,
    compute_manifest,
    load_manifest_full,
    load_signing_key,
    write_manifest,
)


def _sentinel_repo_root() -> Path:
    # `sentinel/cli/verify_rules.py` -> `<repo>`
    return Path(__file__).parent.parent.parent


def add_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "verify-rules",
        help="Check rule files against rules-manifest.json (or regenerate)",
    )
    p.add_argument(
        "--update", action="store_true",
        help="Write the current rule hashes to rules-manifest.json. "
             "Signs the manifest if an HMAC key is available. "
             "Use after intentionally adding/removing/modifying a rule.",
    )
    p.add_argument(
        "--require-signature", action="store_true",
        help="Fail closed (exit 1) unless the manifest carries a signature "
             "that verifies against the available key. Use in CI / Overmind. "
             "On --update, refuse to write an unsigned manifest.",
    )
    p.add_argument(
        "--json", action="store_true",
        help="Emit drift + signature report as JSON to stdout",
    )
    p.add_argument(
        "--manifest", type=Path, default=None,
        help=f"Override manifest path (default: <repo>/{DEFAULT_MANIFEST_REL})",
    )
    p.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> int:
    repo_root = _sentinel_repo_root()
    rules_root = repo_root / "sentinel" / "rules"
    if not rules_root.is_dir():
        print(
            f"[verify-rules] rule dir not found at {rules_root}",
            file=sys.stderr,
        )
        return 2
    manifest_path = args.manifest or (repo_root / DEFAULT_MANIFEST_REL)
    current = compute_manifest(rules_root)
    key = load_signing_key(repo_root)

    if args.update:
        return _run_update(args, manifest_path, current, key)

    return _run_check(args, manifest_path, current, key)


def _run_update(
    args: argparse.Namespace,
    manifest_path: Path,
    current: dict[str, str],
    key: bytes | None,
) -> int:
    if args.require_signature and key is None:
        msg = (
            "[verify-rules] --require-signature: refusing to write an UNSIGNED "
            f"manifest — no key found (set ${SIGNING_KEY_ENV} or the gitignored "
            "key file)."
        )
        if args.json:
            print(json.dumps({"status": "no_key", "action": "update_refused"}))
        else:
            print(msg, file=sys.stderr)
        return 2

    write_manifest(manifest_path, current, key=key)
    signed = key is not None
    if args.json:
        print(json.dumps({
            "status": "updated",
            "signed": signed,
            "rule_count": len(current),
            "path": str(manifest_path),
        }))
    else:
        state = "SIGNED" if signed else "UNSIGNED (no key found)"
        print(
            f"[verify-rules] wrote {len(current)} rule hash(es) to "
            f"{manifest_path} — {state}",
        )
        if not signed:
            print(
                f"[verify-rules] note: set ${SIGNING_KEY_ENV} (or the key file) "
                "and re-run --update to sign.",
                file=sys.stderr,
            )
    return 0


def _run_check(
    args: argparse.Namespace,
    manifest_path: Path,
    current: dict[str, str],
    key: bytes | None,
) -> int:
    doc = load_manifest_full(manifest_path)
    if doc is None:
        msg = (
            f"[verify-rules] no manifest at {manifest_path}; "
            "run with --update to create one"
        )
        if args.json:
            print(json.dumps({"status": "no_manifest", "path": str(manifest_path)}))
        else:
            print(msg, file=sys.stderr)
        return 2

    report = compare(current, doc.rules)
    sig_status = check_signature(doc, key)

    # A signature MISMATCH is tamper: fail closed regardless of flags.
    # (Enum identity via `is` — not a MAC comparison; the actual HMAC check
    # uses hmac.compare_digest in rule_integrity.verify_signature.)
    sig_fail = sig_status is SignatureStatus.MISMATCH
    # Under --require-signature, "no signature" and "no key" are also failures.
    if args.require_signature and sig_status in (
        SignatureStatus.NO_SIGNATURE, SignatureStatus.NO_KEY
    ):
        sig_fail = True

    if args.json:
        out: dict[str, Any] = {
            "status": "drift" if report.has_drift else "ok",
            "added": report.added,
            "removed": report.removed,
            "modified": report.modified,
            "in_sync_count": len(report.in_sync),
            "signature": sig_status.value,
            "signature_algo": doc.algo,
            "require_signature": bool(args.require_signature),
            "signature_failed": sig_fail,
        }
        print(json.dumps(out, indent=2))
    else:
        print(report.summary())
        print(_signature_line(sig_status, args.require_signature))

    return 1 if (report.has_drift or sig_fail) else 0


def _signature_line(status: SignatureStatus, required: bool) -> str:
    if status is SignatureStatus.OK:
        return "signature OK (HMAC verified)"
    if status is SignatureStatus.MISMATCH:
        return "signature MISMATCH — manifest was signed with a different key or tampered (TAMPER; fail-closed)"
    if status is SignatureStatus.NO_SIGNATURE:
        tail = " (FAIL: --require-signature set)" if required else " (hashes verified; run --update with a key to sign)"
        return "signature ABSENT — manifest is unsigned (legacy v1)" + tail
    # NO_KEY
    tail = " (FAIL: --require-signature set)" if required else " (hashes verified only; set the key to verify the signature)"
    return f"signature UNVERIFIED — signed manifest but no key available (${SIGNING_KEY_ENV})" + tail
