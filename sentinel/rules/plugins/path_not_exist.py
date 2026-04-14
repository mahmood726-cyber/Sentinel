"""P0-path-not-exist: portfolio-scoped. Every project in the manifest must
have a path that resolves on disk. Missing paths = BLOCK."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P0-path-not-exist"
SEVERITY = Severity.BLOCK
SOURCE = "workflow.md#exact-path-contract"
SCOPE = "portfolio"


def check(ctx: RepoContext) -> List[Verdict]:
    pi_root = ctx.project_index_root
    assert pi_root is not None, "portfolio scope guarantees project_index_root"

    manifest_path = pi_root / "agent-records" / "restart-manifest.json"
    now = datetime.now(timezone.utc)

    if not manifest_path.is_file():
        return [
            Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(pi_root),
                file=None,
                line=None,
                detail=f"manifest missing at {manifest_path}",
                fix_hint="restore restart-manifest.json before any lifecycle promotion",
                source=SOURCE,
                timestamp=now,
            )
        ]

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return [
            Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(pi_root),
                file=str(manifest_path),
                line=None,
                detail=f"manifest unreadable: {e}",
                fix_hint="repair manifest JSON",
                source=SOURCE,
                timestamp=now,
            )
        ]

    verdicts: List[Verdict] = []
    for proj in data.get("projects", []):
        name = proj.get("name", "<unnamed>")
        path_str = proj.get("path")
        if not path_str:
            continue
        if not Path(path_str).exists():
            verdicts.append(
                Verdict(
                    rule_id=ID,
                    severity=SEVERITY,
                    repo=path_str,
                    file=None,
                    line=None,
                    detail=f"project {name!r} declares path {path_str} but it does not exist",
                    fix_hint="restore path or demote lifecycle status to MISSING",
                    source=SOURCE,
                    timestamp=now,
                )
            )
    return verdicts
