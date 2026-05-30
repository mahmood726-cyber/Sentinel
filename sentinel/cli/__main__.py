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
from sentinel.cli import triage as triage_cmd
from sentinel.cli import verify_rules as verify_rules_cmd


def _reconfigure_stdio_to_utf8() -> None:
    # Windows default is cp1252 which cannot encode e.g. ∩ (U+2229) that
    # appears legitimately in statistics source code. Reconfigure once at
    # entry so every subcommand's print() is safe. Silently skip if stdout
    # has been replaced (e.g. test capture with StringIO).
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    _reconfigure_stdio_to_utf8()
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
    verify_rules_cmd.add_subparser(sub)
    triage_cmd.add_subparser(sub)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
