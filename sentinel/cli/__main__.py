"""Entry point: `python -m sentinel ...` or `sentinel ...`."""
from __future__ import annotations
import argparse
import sys

from sentinel.cli import bypass_log as bypass_log_cmd
from sentinel.cli import dashboard as dashboard_cmd
from sentinel.cli import explain as explain_cmd
from sentinel.cli import install_hook as install_hook_cmd
from sentinel.cli import list_rules as list_rules_cmd
from sentinel.cli import scan as scan_cmd
from sentinel.cli import sweep as sweep_cmd


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel")
    sub = parser.add_subparsers(dest="command", required=True)
    scan_cmd.add_subparser(sub)
    list_rules_cmd.add_subparser(sub)
    explain_cmd.add_subparser(sub)
    install_hook_cmd.add_install_subparser(sub)
    install_hook_cmd.add_uninstall_subparser(sub)
    bypass_log_cmd.add_subparser(sub)
    sweep_cmd.add_subparser(sub)
    dashboard_cmd.add_subparser(sub)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
