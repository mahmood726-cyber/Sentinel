"""Entry point: `python -m sentinel ...` or `sentinel ...`."""
from __future__ import annotations
import argparse
import sys

from sentinel.cli import scan as scan_cmd


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel")
    sub = parser.add_subparsers(dest="command", required=True)
    scan_cmd.add_subparser(sub)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
