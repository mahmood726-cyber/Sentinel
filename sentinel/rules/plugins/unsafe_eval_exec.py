# sentinel:skip-file — docstring + patterns contain the bad forms by design.
"""P0-unsafe-eval-exec: BLOCK on `eval(...)` / `exec(...)` of a NON-literal
argument — the canonical arbitrary-code-execution sink, and a common
AI-generated-code failure mode (agents reach for eval() to "parse" or
"compute" dynamic input).

Detection is false-positive-resistant: string literals and comments are
blanked to whitespace BEFORE matching, so `eval("1 + 1")` collapses to
`eval(        )` (literal arg → ignored) while `eval(user_input)` or
`exec(payload)` keep an identifier/expression argument → fire.

    eval(expr)          # BAD — code-exec sink on dynamic input
    exec(generated)     # BAD
    eval("2 + 2")       # OK — pure literal (blanked before match)
    ast.literal_eval(x) # OK — not matched (must be a bare eval/exec call)

BLOCK: the failure is silent (works in tests, RCE in production) — same
rationale as P0-hmac-compare-eq.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import iter_repo_files
from sentinel.io.skip_marker import has_skip_marker, line_is_suppressed

ID = "P0-unsafe-eval-exec"
SEVERITY = Severity.BLOCK
SOURCE = "lessons.md#code-quality (eval/exec on dynamic input is an RCE sink)"
SCOPE = "repo"

MAX_FILE_BYTES = 5_000_000
PY_EXCLUDE_DIRS = (".venv", "venv", "__pycache__", "build", "dist",
                   ".tox", ".pytest_cache", "node_modules")

# Bare eval(/exec( call (not a .attr like ast.literal_eval / obj.eval), whose
# first non-space arg char is an identifier-start or open-paren (i.e. an
# expression), NOT a closing paren (empty after string-blanking) or a digit.
_CALL_RE = re.compile(r"(?<![\w.])(eval|exec)\(\s*([A-Za-z_(])")

_LINE_COMMENT_RE = re.compile(r"#[^\n]*")
_STRING_RE = re.compile(
    r"'''(?:\\.|.)*?'''|\"\"\"(?:\\.|.)*?\"\"\""
    r"|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"",
    re.DOTALL,
)


def _strip_noise(text: str) -> str:
    def _ws(m):
        return " " * (m.end() - m.start())
    return _LINE_COMMENT_RE.sub(_ws, _STRING_RE.sub(_ws, text))


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


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
        if "eval(" not in text and "exec(" not in text:
            continue
        stripped = _strip_noise(text)
        lines = text.splitlines()
        rel = path.relative_to(root).as_posix()
        for m in _CALL_RE.finditer(stripped):
            fn = m.group(1)
            line_no = _line_of(text, m.start())
            cur = lines[line_no - 1] if line_no - 1 < len(lines) else ""
            prv = lines[line_no - 2] if line_no - 2 >= 0 else ""
            if line_is_suppressed(cur, prv, ID):
                continue
            verdicts.append(Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(root),
                file=rel,
                line=line_no,
                detail=f"`{fn}(...)` called on a non-literal argument — arbitrary-code-execution sink",
                fix_hint=("avoid eval/exec on dynamic input; use ast.literal_eval for data, "
                          "a dispatch dict for behavior, or json.loads for parsing"),
                source=SOURCE,
                timestamp=now,
            ))
    return verdicts
