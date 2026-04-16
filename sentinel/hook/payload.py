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
  # Reject discard targets — redirecting the bypass log to /dev/null or
  # similar would create a silent-bypass hole (an attacker could bypass
  # and simultaneously erase the audit trail). Fail closed.
  case "$log_path" in
    /dev/null|/dev/zero|NUL|nul|""|/dev/stdout|/dev/stderr)
      echo "[Sentinel] SENTINEL_BYPASS_LOG resolves to a discard target ($log_path). Push BLOCKED — pick a real file path or unset the variable." >&2
      exit 1
      ;;
  esac
  if ! mkdir -p "$(dirname "$log_path")" 2>/dev/null; then
    echo "[Sentinel] cannot create bypass-log directory for $log_path. Push BLOCKED — fix the path or unset SENTINEL_BYPASS_LOG." >&2
    exit 1
  fi
  repo="$(git rev-parse --show-toplevel 2>/dev/null || echo unknown)"
  user="$(git config user.name 2>/dev/null || echo unknown)"
  if ! printf '%s\\t%s\\t%s\\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$repo" "$user" >> "$log_path" 2>/dev/null; then
    echo "[Sentinel] failed to append to bypass log ($log_path). Push BLOCKED — check file permissions." >&2
    exit 1
  fi
  echo "[Sentinel] bypass logged to $log_path" >&2
  hook_backup="$(dirname "$0")/pre-push.sentinel-backup"
  if [ -x "$hook_backup" ]; then
    exec "$hook_backup" "$@"
  fi
  exit 0
fi

output="$(python -m sentinel scan --repo "$(git rev-parse --show-toplevel)" 2>&1)"
rc=$?
printf '%s\\n' "$output"

# If Sentinel did not print a verdicts summary, scan crashed BEFORE producing
# a verdict (ImportError, SyntaxError, broken package, wrong Python, etc.).
# Exit code alone is unreliable — Python returns 1 for ImportError, which
# warn mode would silence. Require the verdicts marker as proof-of-run.
if ! printf '%s' "$output" | grep -qE '(\\[Sentinel\\] verdicts:|"verdicts":)'; then
  echo "[Sentinel] scan did NOT produce verdicts — it CRASHED. Push BLOCKED for safety. Fix Sentinel or use SENTINEL_BYPASS=1." >&2
  exit 1
fi

# Sentinel internal error (try/except in scan CLI) — ALWAYS fail-closed.
if [ $rc -ge 10 ]; then
  echo "[Sentinel] scan returned internal-error (exit $rc). Push BLOCKED — fix Sentinel or use SENTINEL_BYPASS=1." >&2
  exit 1
fi

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
