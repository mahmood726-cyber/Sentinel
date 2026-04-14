"""`sentinel install-hook` / `sentinel uninstall-hook` subcommands."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

from sentinel.hook import HookInstallError, install_hook, uninstall_hook


def add_install_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("install-hook", help="Install the Sentinel pre-push hook")
    p.add_argument("--repo", type=Path, required=True, help="Target repo root")
    p.add_argument(
        "--mode", choices=["warn", "block"], default="warn",
        help="Hook mode (default: warn). Warn: findings logged, push allowed. "
             "Block: push aborted on BLOCK. Override per-push via SENTINEL_MODE.",
    )
    p.set_defaults(func=_run_install)


def add_uninstall_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("uninstall-hook", help="Uninstall the Sentinel pre-push hook")
    p.add_argument("--repo", type=Path, required=True, help="Target repo root")
    p.set_defaults(func=_run_uninstall)


def _run_install(args: argparse.Namespace) -> int:
    try:
        install_hook(args.repo, mode=args.mode)
    except HookInstallError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"[Sentinel] hook installed at {args.repo}/.git/hooks/pre-push (mode={args.mode})")
    return 0


def _run_uninstall(args: argparse.Namespace) -> int:
    uninstall_hook(args.repo)
    print(f"[Sentinel] hook uninstalled from {args.repo}")
    return 0
