"""P1-js-scripts-resolvable: WARN when package.json scripts reference files that don't exist.

Catches the pattern where package.json declares npm scripts that invoke
local files (`node scripts/build.js`, `bash ./deploy.sh`) but those files
aren't actually tracked in the repo. Fresh cloners hit ENOENT on every
script call.

Triggering incident: HTA Artifact's package.json declared 8+ npm scripts
referencing files in scripts/ (build, review:panel, validate:reference,
validate:determinism, bench:ci, coverage:report, external:export:r,
external:sync) — but scripts/ was never committed. `npm run quality:gate`
would have failed immediately.

Heuristic: extract any token matching a file-like path (contains / or \\,
ends in a known extension) from each script value, then verify the file
exists. Bare commands like `jest` / `eslint .` / `tsc --noEmit` don't
match the heuristic and aren't flagged.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Set

from sentinel.core import RepoContext, Severity, Verdict


ID = "P1-js-scripts-resolvable"
SEVERITY = Severity.WARN
SOURCE = "lessons.md#code-quality"
SCOPE = "repo"

# Known script file extensions that definitely reference local files
SCRIPT_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".sh", ".bash", ".py", ".R", ".rb"}

# Token pattern: captures filepath-like tokens (must contain / or \ or ./ prefix)
# Examples matched: scripts/build.js, ./deploy.sh, src/cli.py
# Examples NOT matched: jest, eslint, tsc, npm, node
PATH_TOKEN_RE = re.compile(
    r"(?:\./)?([A-Za-z0-9_][\w./\\-]*\.[A-Za-z]{1,5})"
)


def _extract_file_refs(script_cmd: str) -> Set[str]:
    refs = set()
    for match in PATH_TOKEN_RE.finditer(script_cmd):
        tok = match.group(1)
        suffix = Path(tok).suffix
        # Only flag tokens whose extension is a known script file type
        if suffix in SCRIPT_EXTENSIONS:
            refs.add(tok.lstrip("./").replace("\\", "/"))
    return refs


def check(ctx: RepoContext) -> List[Verdict]:
    pkg_path = ctx.repo_root / "package.json"
    if not pkg_path.is_file():
        return []

    try:
        pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    scripts = pkg.get("scripts") or {}
    if not isinstance(scripts, dict):
        return []

    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []

    for script_name, script_cmd in scripts.items():
        if not isinstance(script_cmd, str):
            continue
        for ref in _extract_file_refs(script_cmd):
            target = ctx.repo_root / ref
            if not target.is_file():
                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=SEVERITY,
                    repo=str(ctx.repo_root),
                    file="package.json",
                    line=None,
                    detail=(
                        f"script {script_name!r} references {ref!r} "
                        "but that file does not exist in the repo"
                    ),
                    fix_hint=(
                        f"either commit {ref} or remove/rename the "
                        f"{script_name!r} script"
                    ),
                    source=SOURCE,
                    timestamp=now,
                ))

    return verdicts
