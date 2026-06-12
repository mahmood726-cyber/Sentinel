"""P1-aact-capsule-leak: the AACT-flavored echo of the placeholder-leak family
(lessons.md 2026-05-24: Python None -> JS literal, unfilled tokens). Layer-3
net behind the generator's js_val() (L1) and emit-time guard (L2).

Scope: only *-capsule.html files. WARN by default; promote to BLOCK with
SENTINEL_AACT_CAPSULE_LEAK_BLOCK=1. Narrow patterns only (FP-audit lesson).

Override: `<!-- sentinel:skip-file -->`.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import path_allowed

ID = "P1-aact-capsule-leak"
SEVERITY = Severity.WARN
SOURCE = "lessons.md#placeholder-leak:2026-05-24-rapidmeta-none-jsleak"
SCOPE = "repo"

_BLOCK = os.environ.get("SENTINEL_AACT_CAPSULE_LEAK_BLOCK") == "1"
EXCLUDE_DIRS = frozenset(("node_modules", "__pycache__", ".git", ".pytest_cache", ".venv", "venv", "build", "dist"))

# patterns checked inside <script> blocks (the JS payload)
_SCRIPT_PATS = [
    (re.compile(r"[,:\[(]\s*None\b"), "bare Python None in JS object/array"),
    (re.compile(r"\bNaN\b"), "NaN literal (js_val allow_nan should have caught this)"),
    (re.compile(r"\bInfinity\b"), "Infinity literal"),
    (re.compile(r"__AACT_\w+"), "residual unfilled template token"),
]
# patterns checked in rendered prose
_PROSE_PATS = [
    (re.compile(r"\bwith n participants\b"), "unfilled 'n participants' token"),
    (re.compile(r"\bNone (?:trials|participants|studies)\b"), "leaked None count"),
]
_SCRIPT_BLOCK_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)
# Only the interpolated CAPSULE JSON literal can carry a Python->JS leak. The
# static engine code legitimately uses Infinity/NaN handling, so we scan only
# the payload (FP-audit lesson: narrow the match, don't weaken detection).
_CAPSULE_LITERAL_RE = re.compile(r"const\s+CAPSULE\s*=\s*(\{.*\});")


def _line_of(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    sev = Severity.BLOCK if _BLOCK else Severity.WARN
    out: List[Verdict] = []
    root = ctx.repo_root
    for p in root.rglob("*-capsule.html"):
        if not path_allowed(root, p):
            continue  # honor `scan --diff` changed-file scope
        if any(part in EXCLUDE_DIRS for part in p.parts):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "sentinel:skip-file" in text:
            continue
        rel = p.relative_to(root).as_posix()

        lit = _CAPSULE_LITERAL_RE.search(text)
        payload = lit.group(1) if lit else ""
        for rx, why in _SCRIPT_PATS:
            m = rx.search(payload)
            if m:
                out.append(Verdict(rule_id=ID, severity=sev, repo=str(root), file=rel,
                    line=None, detail=f"placeholder leak in capsule payload: {why} ({m.group(0)!r})",
                    fix_hint="route every Python->JS value through js_val(); rebuild the capsule",
                    source=SOURCE, timestamp=now))
        for rx, why in _PROSE_PATS:
            m = rx.search(text)
            if m:
                out.append(Verdict(rule_id=ID, severity=sev, repo=str(root), file=rel,
                    line=_line_of(text, m.start()), detail=f"placeholder leak in capsule prose: {why}",
                    fix_hint="fill the value in the generator; never emit the literal token",
                    source=SOURCE, timestamp=now))
    return out
