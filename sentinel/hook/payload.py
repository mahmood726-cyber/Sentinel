"""The shell script that Sentinel installs as .git/hooks/pre-push.

SENTINEL_MARKER is a unique banner that lets us detect whether a hook
file was installed by Sentinel (vs. an unrelated user hook)."""
from __future__ import annotations

SENTINEL_MARKER = "# === SENTINEL PRE-PUSH HOOK (do not edit above this line) ==="

HOOK_SCRIPT = f"""#!/bin/sh
{SENTINEL_MARKER}
if [ "${{SENTINEL_BYPASS:-0}}" = "1" ]; then
  log_path="${{SENTINEL_BYPASS_LOG:-$HOME/.sentinel-logs/bypass.log}}"
  mkdir -p "$(dirname "$log_path")"
  repo="$(git rev-parse --show-toplevel 2>/dev/null || echo unknown)"
  user="$(git config user.name 2>/dev/null || echo unknown)"
  printf '%s\\t%s\\t%s\\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$repo" "$user" >> "$log_path"
  echo "[Sentinel] bypass logged to $log_path" >&2
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
