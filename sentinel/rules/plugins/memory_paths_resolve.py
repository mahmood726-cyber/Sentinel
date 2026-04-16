"""P2-memory-paths-resolve: WARN on Claude memory files referencing non-existent paths.

Portfolio-scope rule. Reads memory files under the configured memory
dir (defaults to `C:\\Users\\user\\.claude\\projects\\C--Users-user\\memory`
on Windows), grep-extracts Windows absolute paths from backtick-wrapped
references, verifies each `path.exists()`, WARNs on MISSING.

Triggering incident: 2026-04-16 reconcile. sentinel.md shipped 3 paths
that were wrong — Denominator_Calibrated_Living_NMA, metasprint-autopilot,
and 501MLM_Submission had all moved under C:\\Models\\ or C:\\Projects\\
but memory was never updated. Separate audit turn to reconcile; this
rule surfaces drift at scan time.

Severity: WARN. A broken memory path doesn't corrupt code, but it slows
down future sessions and erodes trust in memory as ground truth.

Skips:
  - Glob templates (`C:\\Projects\\*_LivingMeta`)
  - Historical 'was here, now gone' Downloads/ references (prose about
    prior locations, not assertions about current state)

Env var override for tests / alternate setups:
  SENTINEL_MEMORY_DIR=/path/to/memory/dir

Companion tool: `C:\\ProjectIndex\\verify_memory_paths.py` runs the same
check offline (pre-push / CI).
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P2-memory-paths-resolve"
SEVERITY = Severity.WARN
SOURCE = "lessons.md#portfolio-audit-patterns"
SCOPE = "portfolio"

DEFAULT_MEMORY_DIR = Path(
    r"C:\Users\user\.claude\projects\C--Users-user\memory"
)

# Backtick-wrapped Windows path: `C:\...` or `C:/...`
BACKTICK_PATH_RE = re.compile(r"`([A-Z]):([\\/][^`]+?)`")

# Skip these patterns: glob templates + historical references
SKIP_FRAGMENTS = (
    "*",            # glob — `C:\Projects\*_LivingMeta`
    "/Downloads/",  # historical prose — "was here, now gone"
    "\\Downloads\\",
)


def _memory_dir() -> Path:
    override = os.environ.get("SENTINEL_MEMORY_DIR")
    if override:
        return Path(override)
    return DEFAULT_MEMORY_DIR


def _available_drives() -> set:
    """Return the set of drive letters currently accessible (e.g. {'C', 'D'})."""
    import string
    return {
        letter for letter in string.ascii_uppercase
        if os.path.exists(f"{letter}:/")
    }


def check(ctx: RepoContext) -> List[Verdict]:
    memory = _memory_dir()
    if not memory.is_dir():
        return []

    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    drives_available = _available_drives()

    for md_file in sorted(memory.glob("*.md")):
        try:
            text = md_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        seen = set()  # dedupe per-file
        for lineno, line in enumerate(text.splitlines(), start=1):
            for match in BACKTICK_PATH_RE.finditer(line):
                drive, rest = match.group(1), match.group(2)
                found = f"{drive}:{rest}".rstrip("\\/")
                if any(frag in found for frag in SKIP_FRAGMENTS):
                    continue
                key = (found.lower(), lineno)
                if key in seen:
                    continue
                seen.add(key)
                if Path(found).exists():
                    continue

                # Distinguish "drive offline" (INFO — transient, not drift)
                # from "drive mounted but path missing" (WARN — real drift).
                drive_letter = drive.upper()
                if drive_letter not in drives_available:
                    verdicts.append(Verdict(
                        rule_id=ID,
                        severity=Severity.INFO,
                        repo=str(memory),
                        file=md_file.name,
                        line=lineno,
                        detail=(
                            f"{md_file.name}:{lineno} references path on "
                            f"offline drive {drive_letter}: "
                            f"{found!r} — not drift, drive not mounted"
                        ),
                        fix_hint=(
                            f"mount {drive_letter}: drive and rerun scan; "
                            "if the drive is intentionally offline, ignore"
                        ),
                        source=SOURCE,
                        timestamp=now,
                    ))
                    continue

                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=SEVERITY,
                    repo=str(memory),
                    file=md_file.name,
                    line=lineno,
                    detail=(
                        f"{md_file.name}:{lineno} references MISSING path "
                        f"{found!r}"
                    ),
                    fix_hint=(
                        "update memory to the correct path, or remove the "
                        "reference if the project was archived"
                    ),
                    source=SOURCE,
                    timestamp=now,
                ))

    return verdicts
