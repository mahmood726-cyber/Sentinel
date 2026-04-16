"""`sentinel bypass-log` — view or clear the bypass log."""
from __future__ import annotations
import argparse
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


def add_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("bypass-log", help="View or clear the bypass log")
    p.add_argument("--clear", action="store_true", help="Empty the bypass log file")
    p.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> int:
    try:
        path = _log_path()
    except BypassLogPathError as exc:
        print(f"[Sentinel] {exc}", flush=True)
        return 1
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
