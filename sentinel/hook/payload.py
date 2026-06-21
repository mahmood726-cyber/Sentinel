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
  # Tamper-evident hash chain: each entry's trailing field is
  # sha256(prev_chain + this_entry). Editing or deleting any past line breaks
  # the chain for every line after it, so the user-writable log can no longer
  # be silently rewritten to hide a bypass. `sentinel bypass-log --verify`
  # validates the chain. Degrades to an unchained line if sha256sum is absent.
  entry="$(printf '%s\\t%s\\t%s' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$repo" "$user")"
  if command -v sha256sum >/dev/null 2>&1; then
    prev_chain="$(tail -n 1 "$log_path" 2>/dev/null | awk -F'\\t' 'NF>=4{{print $4}}')"
    chain="$(printf '%s%s' "$prev_chain" "$entry" | sha256sum | cut -d' ' -f1)"
    line="$(printf '%s\\t%s' "$entry" "$chain")"
  else
    line="$entry"
  fi
  if ! printf '%s\\n' "$line" >> "$log_path" 2>/dev/null; then
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

# Pre-push by default scans only the diff vs the remote's HEAD —
# typical PRs touch <10 files so this drops a 2-minute full scan to
# ~1s. Operators who want the old whole-tree behavior can set
# SENTINEL_DIFF_BASE=full. Set SENTINEL_DIFF_BASE=<ref> to pick a
# specific base (e.g. origin/main, origin/master, HEAD~5).
#
# Auto-detection tries origin/HEAD first (the GitHub default-branch
# pointer), then origin/main, then origin/master, then HEAD~1.
# If nothing resolves, fall back to full-tree scan rather than skipping
# the scan entirely — "no diff base" should never silently bypass.
REPO_TOPLEVEL="$(git rev-parse --show-toplevel)"
DIFF_BASE="${{SENTINEL_DIFF_BASE:-}}"

if [ "$DIFF_BASE" = "full" ]; then
  SCAN_ARGS=""
elif [ -n "$DIFF_BASE" ]; then
  SCAN_ARGS="--diff --base-ref $DIFF_BASE"
else
  # Auto-detect base ref
  for candidate in origin/HEAD origin/main origin/master HEAD~1; do
    if git -C "$REPO_TOPLEVEL" rev-parse --verify --quiet "$candidate" >/dev/null 2>&1; then
      SCAN_ARGS="--diff --base-ref $candidate"
      break
    fi
  done
  SCAN_ARGS="${{SCAN_ARGS:-}}"
fi

output="$(python -m sentinel scan --repo "$REPO_TOPLEVEL" $SCAN_ARGS 2>&1)"
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
