"""P1-py-parse-check: BLOCK pushes containing .py files that fail python's parser.

Parallel to P1-js-parse-check (2026-04-15). Catches Python SyntaxErrors
(malformed f-strings, unmatched brackets, bad indentation) before they
reach a submission-ready state.

Triggering incident: saarc-e156-students 2026-04-16. Six generator
scripts across 3 paper groups had the pattern
  print(f"  {'Karachi's Global Trial Share'}")
— the inner single-quote terminated the inner string, producing
SyntaxError on any attempt to import or run the file. They sat on disk
unmodified for weeks because no one ever ran them. A parse-check at
push time would have surfaced the bug on commit day.

Implementation: in-process `compile(source, path, "exec")`. The prior
`python -m py_compile <file>` subprocess was ~30-80ms/file (interpreter
startup dominated); in-process is ~1ms/file. A 200-file repo went from
~10s to ~0.2s of pre-push overhead. `compile()` does not execute the
module — it only parses — so the isolation argument for subprocess no
longer applies.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import PY_EXCLUDE_DIRS, iter_repo_files


ID = "P1-py-parse-check"
SEVERITY = Severity.BLOCK
SOURCE = "lessons.md#python-module-test-collection-traps"
SCOPE = "repo"
SKIP_FILE_MARKER = "sentinel:skip-file"
SKIP_MARKER_SCAN_BYTES = 1024


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    repo_prefix = str(ctx.repo_root)

    for path in iter_repo_files(ctx.repo_root, "*.py", PY_EXCLUDE_DIRS):
        rel = path.relative_to(ctx.repo_root).as_posix()
        if _file_has_skip_marker(path):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            verdicts.append(Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=repo_prefix,
                file=rel,
                line=None,
                detail=f"unreadable ({type(e).__name__})",
                fix_hint=f"restore file permissions on {rel}",
                source=SOURCE,
                timestamp=now,
            ))
            continue

        try:
            compile(source, rel, "exec")
        except SyntaxError as e:
            msg = (e.msg or "syntax error").replace(repo_prefix, "").strip()
            line_no = e.lineno
            offset = e.offset
            detail = f"{msg} at line {line_no}"
            if offset:
                detail += f", col {offset}"
            verdicts.append(Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=repo_prefix,
                file=rel,
                line=line_no,
                detail=detail[:300],
                fix_hint=(
                    f"open {rel} at line {line_no} and fix the syntax error; "
                    f"reproduce locally with `python -m py_compile {rel}`"
                ),
                source=SOURCE,
                timestamp=now,
            ))
        except ValueError as e:
            # Raised when source contains NUL bytes — treat as parse failure.
            verdicts.append(Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=repo_prefix,
                file=rel,
                line=None,
                detail=f"source contains non-text bytes ({type(e).__name__})",
                fix_hint=f"confirm {rel} is valid utf-8 text, not binary",
                source=SOURCE,
                timestamp=now,
            ))

    return verdicts


def _file_has_skip_marker(file_path: Path) -> bool:
    try:
        head = file_path.read_bytes()[:SKIP_MARKER_SCAN_BYTES]
    except OSError:
        return False
    return SKIP_FILE_MARKER in head.decode("utf-8", errors="replace")
