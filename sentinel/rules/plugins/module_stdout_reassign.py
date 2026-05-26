# sentinel:skip-file — this module's docstring shows the bad pattern as
# the example of what NOT to write, which would otherwise self-flag.
"""P1-module-stdout-reassign: WARN on module-level sys.stdout reassignment
that doesn't exclude pytest.

Past incident (lessons.md "Module-level sys.stdout reassignment kills pytest
capture", 2026-04-16; reproduced 2× in May 2026 sessions):

    # WRONG — breaks pytest capture when this module is imported under pytest
    if sys.platform == "win32":
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", ...)

When pytest imports a module containing this pattern (during test
collection or as a transitive import), the reassignment replaces
pytest's capture tmpfile wrapper with a fresh TextIOWrapper. Pytest's
internal state still points at the old wrapper, which is now closed.
Later print() calls — or pytest's own teardown — raise
`ValueError: I/O operation on closed file`. The error often manifests
far from the reassignment site (e.g. "0 tests collected" with an
opaque traceback during pytest_collect_file).

The fix is either of:

    # SAFE — opt out when pytest is active
    if sys.platform == "win32" and "pytest" not in sys.modules:
        sys.stdout = io.TextIOWrapper(...)

    # SAFE — defer to script-only invocation
    if __name__ == "__main__":
        if sys.platform == "win32":
            sys.stdout = io.TextIOWrapper(...)

    # SAFE — inside a function called from main()
    def main():
        if sys.platform == "win32":
            sys.stdout = io.TextIOWrapper(...)

This rule scans every tracked .py file for the bad pattern and emits a
WARN. False-positive risk is low because the pattern is specific
(`sys.stdout = io.TextIOWrapper`) and the guard requirements are
narrow.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import iter_repo_files
from sentinel.io.skip_marker import has_skip_marker


ID = "P1-module-stdout-reassign"
SEVERITY = Severity.WARN
SOURCE = "lessons.md#python-module--test-collection-traps  (Module-level sys.stdout reassignment kills pytest capture, 2026-04-16)"
SCOPE = "repo"

MAX_FILE_BYTES = 2_000_000

# Match `sys.stdout = io.TextIOWrapper(...)` or `sys.stderr = io.TextIOWrapper(...)`.
# Captures the leading whitespace so we can decide if the line is at module
# top level vs nested inside a def / class.
REASSIGN_RE = re.compile(
    r"^(?P<indent>[ \t]*)sys\.(?:stdout|stderr)\s*=\s*io\.TextIOWrapper\b",
    re.MULTILINE,
)

# A line is "guarded by pytest exclusion" if any of the enclosing `if` lines
# (within 10 lines preceding) contain one of these markers.
PYTEST_GUARD_RE = re.compile(
    r'["\']pytest["\']\s+not\s+in\s+sys\.modules'
    r'|sys\.modules\.get\(["\']pytest["\']\)\s+is\s+None'
    r'|__name__\s*==\s*["\']__main__["\']'
)


def _is_inside_function(lines: list[str], line_idx: int) -> bool:
    """Walk backward and check if any preceding non-blank line at column 0
    is a `def `/`class ` declaration. Stops at first column-0 statement that
    isn't blank/comment/decorator."""
    for i in range(line_idx - 1, -1, -1):
        ln = lines[i].rstrip()
        if not ln:
            continue
        # Continue past decorators and comments at any indent
        stripped = ln.lstrip()
        if stripped.startswith("#") or stripped.startswith("@"):
            continue
        # Found something at column 0
        if not ln.startswith((" ", "\t")):
            return ln.lstrip().startswith(("def ", "async def ", "class "))
    return False


def _is_guarded(lines: list[str], line_idx: int) -> bool:
    """Walk backward up to 10 lines looking for an `if` whose condition
    excludes pytest or guards on __main__. Stops at first column-0 statement
    that isn't a guard."""
    # If the reassignment is inside a function/class, the function context
    # is already a guard.
    if _is_inside_function(lines, line_idx):
        return True
    # Look back for an `if ... pytest not in sys.modules` line within 10 lines.
    for i in range(max(0, line_idx - 10), line_idx):
        ln = lines[i]
        if PYTEST_GUARD_RE.search(ln):
            return True
    return False


PY_EXCLUDE_DIRS = (".venv", "venv", "__pycache__", "build", "dist",
                   ".tox", ".pytest_cache", "node_modules", "archive")


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    root = ctx.repo_root
    for path in iter_repo_files(root, "*.py", PY_EXCLUDE_DIRS):
        if has_skip_marker(path):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "sys.stdout" not in text and "sys.stderr" not in text:
            continue
        rel = path.relative_to(root).as_posix()
        lines = text.splitlines()
        for m in REASSIGN_RE.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            line_idx = line_no - 1
            if _is_guarded(lines, line_idx):
                continue
            verdicts.append(Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(root),
                file=rel,
                line=line_no,
                detail=(
                    "module-level `sys.stdout = io.TextIOWrapper(...)` "
                    "without a `\"pytest\" not in sys.modules` guard — "
                    "will corrupt pytest's I/O capture when imported"
                ),
                fix_hint=(
                    "Add `and \"pytest\" not in sys.modules` to the enclosing "
                    "`if sys.platform == \"win32\":` condition, or move the "
                    "reassignment inside a function called from main()"
                ),
                source=SOURCE,
                timestamp=now,
            ))
    return verdicts
