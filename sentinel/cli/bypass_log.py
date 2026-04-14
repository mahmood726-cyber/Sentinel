"""`sentinel bypass-log` — view or clear the bypass log."""
from __future__ import annotations
import argparse
import os
from pathlib import Path


DEFAULT_LOG = Path.home() / ".sentinel-logs" / "bypass.log"


def _log_path() -> Path:
    env = os.environ.get("SENTINEL_BYPASS_LOG")
    return Path(env) if env else DEFAULT_LOG


def add_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("bypass-log", help="View or clear the bypass log")
    p.add_argument("--clear", action="store_true", help="Empty the bypass log file")
    p.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> int:
    path = _log_path()
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
