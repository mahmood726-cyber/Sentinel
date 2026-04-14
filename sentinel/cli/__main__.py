"""Temporary CLI stub — replaced in Task 14 (scan) / Task 15 (list-rules, explain)."""
from __future__ import annotations
import sys


def main(argv: list[str] | None = None) -> int:
    print(
        "sentinel CLI stub — not yet implemented in M1.\n"
        "This stub exists so the [project.scripts] entry point does not crash "
        "while Tasks 2-13 build the core library. The real CLI arrives in "
        "Task 14 (scan) and Task 15 (list-rules, explain).",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
