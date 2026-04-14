"""The shell script that Sentinel installs as .git/hooks/pre-push.

SENTINEL_MARKER is a unique banner that lets us detect whether a hook
file was installed by Sentinel (vs. an unrelated user hook).

The hook supports two modes:
- `block`: BLOCK verdicts abort the push (exit 1).
- `warn`:  BLOCK verdicts are recorded to STUCK_FAILURES.md but push proceeds.

Mode is baked in at install time via {installed_mode}. Env var `SENTINEL_MODE`
overrides at push time (e.g. `SENTINEL_MODE=block git push` to force-block a
warn-installed hook; `SENTINEL_MODE=warn git push` to soft-override block).

Bypass: `SENTINEL_BYPASS=1 git push` skips scanning entirely and logs to
`~/.sentinel-logs/bypass.log`. Bypass is independent of mode.
"""
from __future__ import annotations

SENTINEL_MARKER = "# === SENTINEL PRE-PUSH HOOK (do not edit above this line) ==="


def make_hook_script(mode: str = "block") -> str:
    if mode not in ("warn", "block"):
        raise ValueError(f"mode must be 'warn' or 'block', got {mode!r}")
    return f"""#!/bin/sh
{SENTINEL_MARKER}
MODE="${{SENTINEL_MODE:-{mode}}}"

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

python -m sentinel scan --repo "$(git rev-parse --show-toplevel)"
rc=$?

if [ "$MODE" = "warn" ] && [ "$rc" = "1" ]; then
  echo "[Sentinel] warn mode: findings recorded but push allowed (see STUCK_FAILURES.md)" >&2
  rc=0
fi

if [ $rc -ne 0 ]; then
  echo "[Sentinel] push aborted (exit $rc) — mode=$MODE. Override with SENTINEL_BYPASS=1." >&2
  exit $rc
fi

hook_backup="$(dirname "$0")/pre-push.sentinel-backup"
if [ -x "$hook_backup" ]; then
  exec "$hook_backup" "$@"
fi
exit 0
"""


HOOK_SCRIPT = make_hook_script("block")
