"""The shell script that Sentinel installs as .git/hooks/pre-push.

SENTINEL_MARKER is a unique banner that lets us detect whether a hook
file was installed by Sentinel (vs. an unrelated user hook)."""
from __future__ import annotations

SENTINEL_MARKER = "# === SENTINEL PRE-PUSH HOOK (do not edit above this line) ==="

HOOK_SCRIPT = f"""#!/bin/sh
{SENTINEL_MARKER}
# Sentinel runs first; on exit 0 we chain to any prior hook saved as
# pre-push.sentinel-backup. Bypass with SENTINEL_BYPASS=1.

if [ "${{SENTINEL_BYPASS:-0}}" = "1" ]; then
  echo "[Sentinel] bypass requested via SENTINEL_BYPASS=1" >&2
  hook_backup="$(dirname "$0")/pre-push.sentinel-backup"
  if [ -x "$hook_backup" ]; then
    exec "$hook_backup" "$@"
  fi
  exit 0
fi

python -m sentinel scan --repo "$(git rev-parse --show-toplevel)" --trigger pre-push
rc=$?
if [ $rc -ne 0 ]; then
  echo "[Sentinel] push aborted (exit $rc)" >&2
  exit $rc
fi

hook_backup="$(dirname "$0")/pre-push.sentinel-backup"
if [ -x "$hook_backup" ]; then
  exec "$hook_backup" "$@"
fi
exit 0
"""
