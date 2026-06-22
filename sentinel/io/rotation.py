"""Size-capped log rotation for Sentinel's append-only output files.

Sentinel's finding logs (STUCK_FAILURES.md/.jsonl, sentinel-findings.md/.jsonl)
and the bypass audit log are append-only. Without rotation they grow without
bound — the infra audit (2026-06-20) found a 3.2 MB, 25-day-stale
STUCK_FAILURES.md. Unbounded logs slow every downstream parse (Overmind
aggregates these), blow up git diffs, and bury recent findings.

Policy (deterministic, no time dependency so it stays reproducible):
  - Before an append, if the file already exceeds ``max_bytes``, rotate it to
    ``<name>.1`` (overwriting any previous ``.1``), keeping at most
    ``backup_count`` numbered backups (``.1`` .. ``.N``). Oldest is dropped.
  - Rotation is best-effort and fail-soft: any OSError is swallowed so a
    rotation problem never blocks a scan/append (the append still happens).

This is intentionally a tiny, dependency-free reimplementation of the
``RotatingFileHandler`` rollover so it can guard plain ``Path.open("a")``
appends (writer.py) and the bypass log without routing everything through the
logging module.
"""
from __future__ import annotations

import os
from pathlib import Path

# 2 MB default cap. Large enough to hold a meaningful recent history; small
# enough that the file never becomes the 3.2 MB monster the audit flagged.
DEFAULT_MAX_BYTES = 2 * 1024 * 1024
DEFAULT_BACKUP_COUNT = 3

# Per-machine override (e.g. CI wanting a tighter cap). Parsed fail-soft.
_ENV_MAX_BYTES = "SENTINEL_LOG_MAX_BYTES"


def _resolved_max_bytes(max_bytes: int | None) -> int:
    if max_bytes is not None:
        return max_bytes
    raw = os.environ.get(_ENV_MAX_BYTES, "").strip()
    if raw:
        try:
            value = int(raw)
            if value > 0:
                return value
        except ValueError:
            pass
    return DEFAULT_MAX_BYTES


def rotate_if_needed(
    path: Path,
    max_bytes: int | None = None,
    backup_count: int = DEFAULT_BACKUP_COUNT,
) -> bool:
    """Rotate ``path`` if it is at/over the size cap. Returns True if rotated.

    Fail-soft: returns False and leaves the file untouched on any OSError, so a
    rotation failure never blocks the append that follows.
    """
    cap = _resolved_max_bytes(max_bytes)
    try:
        if not path.exists() or path.stat().st_size < cap:
            return False
    except OSError:
        return False

    try:
        # Drop the oldest, shift each backup up by one, then move current -> .1
        oldest = path.with_name(f"{path.name}.{backup_count}")
        if oldest.exists():
            oldest.unlink()
        for index in range(backup_count - 1, 0, -1):
            src = path.with_name(f"{path.name}.{index}")
            if src.exists():
                src.replace(path.with_name(f"{path.name}.{index + 1}"))
        path.replace(path.with_name(f"{path.name}.1"))
        return True
    except OSError:
        return False
