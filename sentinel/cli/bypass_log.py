"""`sentinel bypass-log` — view, verify, or clear the bypass log."""
from __future__ import annotations
import argparse
import hashlib
import os
from pathlib import Path


DEFAULT_LOG = Path.home() / ".sentinel-logs" / "bypass.log"

# Redirecting the bypass log to one of these would erase the audit trail
# (silent-bypass hole). The hook payload rejects these paths before
# writing; this list keeps the CLI side symmetric so `sentinel bypass-log`
# doesn't pretend to read from /dev/null either.
_DISCARD_TARGETS = frozenset({
    "/dev/null", "/dev/zero", "/dev/stdout", "/dev/stderr",
    "NUL", "nul", "",
})


class BypassLogPathError(Exception):
    """Raised when SENTINEL_BYPASS_LOG resolves to a discard target."""


def _log_path() -> Path:
    env = os.environ.get("SENTINEL_BYPASS_LOG")
    if env is None:
        return DEFAULT_LOG
    # Normalize trailing whitespace but DON'T lowercase — Linux paths are
    # case-sensitive. The Windows NUL/nul variants are enumerated above.
    normalized = env.strip()
    if normalized in _DISCARD_TARGETS:
        raise BypassLogPathError(
            f"SENTINEL_BYPASS_LOG={env!r} resolves to a discard target. "
            f"Pick a real file path or unset the variable."
        )
    return Path(normalized)


def verify_chain(lines: list[str]) -> tuple[bool, int | None, str]:
    """Validate the bypass log's tamper-evident hash chain.

    Each chained line is ``ts<TAB>repo<TAB>user<TAB>chain`` where
    ``chain = sha256(prev_chain + "ts<TAB>repo<TAB>user")``. Returns
    ``(ok, first_bad_lineno, message)``. Unchained legacy lines (3 fields) are
    tolerated but reset the running chain to empty so a later chained entry
    still validates against them — they are reported as advisory, not failures.
    """
    prev_chain = ""
    legacy = 0
    for lineno, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) < 4:
            # Pre-chain entry — can't be cryptographically verified.
            legacy += 1
            prev_chain = ""
            continue
        entry = "\t".join(fields[:3])
        recorded = fields[3]
        expected = hashlib.sha256((prev_chain + entry).encode("utf-8")).hexdigest()
        if recorded != expected:
            return (False, lineno, f"chain broken at line {lineno}: recorded hash does not match")
        prev_chain = recorded
    suffix = f" ({legacy} unchained legacy line(s) skipped)" if legacy else ""
    return (True, None, f"bypass log chain intact{suffix}")


def add_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("bypass-log", help="View, verify, or clear the bypass log")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--clear", action="store_true", help="Empty the bypass log file")
    g.add_argument(
        "--verify", action="store_true",
        help="Validate the tamper-evident hash chain (exit 1 if broken)",
    )
    p.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> int:
    try:
        path = _log_path()
    except BypassLogPathError as exc:
        print(f"[Sentinel] {exc}", flush=True)
        return 1
    if getattr(args, "verify", False):
        if not path.exists() or path.stat().st_size == 0:
            print(f"[Sentinel] bypass log is empty ({path}) — nothing to verify")
            return 0
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        ok, bad_line, message = verify_chain(lines)
        print(f"[Sentinel] {message}")
        return 0 if ok else 1

    if args.clear:
        if path.exists():
            path.write_text("", encoding="utf-8")
            print(f"[Sentinel] bypass log cleared: {path}")
        else:
            print(f"[Sentinel] bypass log is already empty: {path}")
        return 0

    if not path.exists() or path.stat().st_size == 0:
        print(f"[Sentinel] bypass log is empty ({path})")
        return 0

    print(path.read_text(encoding="utf-8", errors="replace"))
    return 0
