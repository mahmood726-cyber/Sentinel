"""P0-aact-snapshot-provenance: a ClinicalTrials.gov/AACT capsule must cite the
exact data snapshot it was built from, and must not claim live/real-time
freshness it does not have.

Scope: only *-capsule.html files (zero findings on repos without capsules, so
this is safe to run portfolio-wide — see MEMORY.md Sentinel FP audit). BLOCK is
deliberately narrow: it fires only when the embedded CAPSULE JSON parses and is
missing a non-empty snapshot_date, or when rendered prose (outside <script>)
claims live freshness with no snapshot reference.

Override: add `<!-- sentinel:skip-file -->` to the capsule.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import path_allowed

ID = "P0-aact-snapshot-provenance"
SEVERITY = Severity.BLOCK
SOURCE = "C:\\Users\\mahmo\\.claude\\projects\\C--Users-mahmo\\memory\\aact_duckdb_dialect.md"
SCOPE = "repo"

EXCLUDE_DIRS = frozenset(("node_modules", "__pycache__", ".git", ".pytest_cache", ".venv", "venv", "build", "dist"))
_CAPSULE_RE = re.compile(r"const\s+CAPSULE\s*=\s*(\{.*?\});", re.DOTALL)
# live-freshness overclaim, excluding the legitimate "live re-run"/"re-pool"
_FRESH_RE = re.compile(r"\b(real-?time|up-?to-the-minute|continuously updated|always current)\b", re.IGNORECASE)
_LEGIT_RE = re.compile(r"live re-run|re-pool", re.IGNORECASE)


def _line_of(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


def _capsule_json(text: str):
    m = _CAPSULE_RE.search(text)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except (ValueError, json.JSONDecodeError):
        return None


def _iter_capsules(root: Path):
    for p in root.rglob("*-capsule.html"):
        if not path_allowed(root, p):
            continue  # honor `scan --diff` changed-file scope
        if any(part in EXCLUDE_DIRS for part in p.parts):
            continue
        yield p


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    out: List[Verdict] = []
    root = ctx.repo_root
    for p in _iter_capsules(root):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "sentinel:skip-file" in text:
            continue
        rel = p.relative_to(root).as_posix()

        cap = _capsule_json(text)
        if cap is not None and not (cap.get("snapshot_date") or "").strip():
            out.append(Verdict(rule_id=ID, severity=Severity.BLOCK, repo=str(root),
                file=rel, line=_line_of(text, text.find("const CAPSULE")),
                detail="capsule CAPSULE JSON has no snapshot_date — cannot cite its AACT data vintage",
                fix_hint="set snapshot_date from the warehouse _meta (engine threads it through provenance)",
                source=SOURCE, timestamp=now))

        # freshness overclaim in rendered prose (skip text inside <script>)
        for m in _FRESH_RE.finditer(text):
            pre = text[max(0, m.start() - 500):m.start()]
            if pre.rfind("<script") > pre.rfind("</script>"):
                continue
            window = text[max(0, m.start() - 200):m.start() + 200]
            if _LEGIT_RE.search(window) or "snapshot" in window.lower():
                continue
            out.append(Verdict(rule_id=ID, severity=Severity.BLOCK, repo=str(root),
                file=rel, line=_line_of(text, m.start()),
                detail=f"capsule claims live freshness ({m.group(0)!r}) but is built from a fixed snapshot",
                fix_hint="state the snapshot date; a snapshot capsule is not live data",
                source=SOURCE, timestamp=now))
    return out
