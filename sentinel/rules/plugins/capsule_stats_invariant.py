"""P1-capsule-stats-invariant: enforce the statistical gotchas (advanced-stats.md)
encoded in a capsule's embedded self-audit. Parses the CAPSULE JSON (no JS
execution) and flags:
  - DL estimator used with k<10 and no documenting note (DL is biased for small k)
  - missing prediction interval when k>=2
  - any self-audit aact_stats check reported as 'fail'

Scope: only *-capsule.html. WARN by default; SENTINEL_CAPSULE_STATS_BLOCK=1 -> BLOCK.
Override: `<!-- sentinel:skip-file -->` or `<!-- sentinel:capsule-stats-allow -->`.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict

ID = "P1-capsule-stats-invariant"
SEVERITY = Severity.WARN
SOURCE = "C:\\Users\\mahmo\\.claude\\rules\\advanced-stats.md"
SCOPE = "repo"

_BLOCK = os.environ.get("SENTINEL_CAPSULE_STATS_BLOCK") == "1"
EXCLUDE_DIRS = frozenset(("node_modules", "__pycache__", ".git", ".pytest_cache", ".venv", "venv", "build", "dist"))
_CAPSULE_RE = re.compile(r"const\s+CAPSULE\s*=\s*(\{.*?\});", re.DOTALL)


def _capsule_json(text: str):
    m = _CAPSULE_RE.search(text)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except (ValueError, json.JSONDecodeError):
        return None


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    sev = Severity.BLOCK if _BLOCK else Severity.WARN
    out: List[Verdict] = []
    root = ctx.repo_root
    for p in root.rglob("*-capsule.html"):
        if any(part in EXCLUDE_DIRS for part in p.parts):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "sentinel:skip-file" in text or "sentinel:capsule-stats-allow" in text:
            continue
        cap = _capsule_json(text)
        if cap is None:
            continue
        rel = p.relative_to(root).as_posix()
        pooled = cap.get("pooled", {}) or {}
        notes = " ".join(str(n) for n in (cap.get("notes") or []))
        k = pooled.get("k")
        method = pooled.get("method")

        if isinstance(k, int) and k < 10 and method == "DL" and "dl_note" not in notes.lower():
            out.append(Verdict(rule_id=ID, severity=sev, repo=str(root), file=rel, line=None,
                detail=f"DL estimator with k={k} (<10) and no documenting note — DL is biased for small k",
                fix_hint="use Paule-Mandel or REML for k<10, or add a dl_note explaining the choice",
                source=SOURCE, timestamp=now))

        if isinstance(k, int) and k >= 2 and pooled.get("pi_lower") is None:
            out.append(Verdict(rule_id=ID, severity=sev, repo=str(root), file=rel, line=None,
                detail=f"no prediction interval reported with k={k} (>=2)",
                fix_hint="report a t_{k-1} prediction interval (Cochrane v6.5)",
                source=SOURCE, timestamp=now))

        stats = (cap.get("self_audit", {}) or {}).get("aact_stats", {}) or {}
        for name, val in stats.items():
            if val == "fail":
                out.append(Verdict(rule_id=ID, severity=sev, repo=str(root), file=rel, line=None,
                    detail=f"capsule self-audit reports statistical check '{name}' = fail",
                    fix_hint="fix the underlying statistic before publishing the capsule",
                    source=SOURCE, timestamp=now))
    return out
