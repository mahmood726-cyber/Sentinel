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

HOOK_GENERATION = 3

SENTINEL_MARKER = "# === SENTINEL PRE-PUSH HOOK (do not edit above this line) ==="

# Earlier scripts this installer still owns, as sha256 of the LF-normalised
# script. Recognition is by exact content, so without this list every hook
# from an older release reads as a user's edited hook and install/uninstall
# refuse it. Census of live repositories, 2026-11-07: all 52 installed hooks
# were one of the first four below, and all were CRLF on disk.
#
# Whenever make_hook_script() changes, add the digests of the script it
# replaces here, in the same commit. Each digest is tied to its source by a
# fixture in tests/fixtures/hooks/.
PREVIOUS_HOOK_SHA256 = frozenset({
    # 7f3f0e5 warn (38 repositories)
    "b23610d6d52cf0bf3a3a846f619ca70be53c9aeed54e883d7fe76545742e543b",
    # 7f3f0e5 block (8 repositories)
    "abb3a02821e62b50b0168a8b097a8bb73f63a58770bdeaecab81b7ebdc86e4f2",
    # f83145f block (3 repositories)
    "53fa825ade871dae76197a9e6cc98e7eb01f8b5b7ee840da36c103e03e155e70",
    # abb6ddb warn (3 repositories)
    "460538d0a6c298b8178e24f64a6c3688d681d9ffb024d70a76f6b78b04874ba1",
    # fdf0741 block and warn (none in the census; what install-hook wrote
    # until the scan moved to `python -P`)
    "195cae7990a3501396af62d94be8e11de14e9d7f19f08441db840b000b9b112f",
    "f49dcf0fdfc928e941e92b634d090736d2a855af172945a6a757f0bf7f453edb",
    # pre-push-7a4e4db-block
    "4108a2369507bd112f6b981d1d092c69316a82bb66176bfb904eae240e6f7b77",
    # pre-push-7a4e4db-warn
    "b9691506b0a80a88441b769d5d84087ab533e9bd331d0aabc42c5fb3a52a51af",
    # pre-push-bcfbafd-block
    "b3b85eb16bceeb1e57578ee1d8494e8878d93881a512611f8013a063674b7796",
    # pre-push-bcfbafd-warn
    "ba66dc2be7aac7baa2741dd1c84bc9a93a0e7e875add6dfbafa618fc3a65fa67",
})


def make_hook_script(mode: str = "block") -> str:
    if mode not in ("warn", "block"):
        raise ValueError(f"mode must be 'warn' or 'block', got {mode!r}")
    return f"""#!/bin/sh
{SENTINEL_MARKER}
# Sentinel hook generation: {HOOK_GENERATION}
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

# Preserve Git's ref records for both Sentinel and a chained user hook.
# The trailing sentinel prevents command substitution stripping newlines.
PUSH_INPUT="$(cat && printf '.')" || {{
  echo "[Sentinel] INTERNAL ERROR: cannot read pre-push input. Push BLOCKED." >&2
  exit 10
}}
PUSH_INPUT="${{PUSH_INPUT%.}}"
# -P prevents a repository-local sentinel/ package replacing the scanner.
output="$(printf '%s' "$PUSH_INPUT" | python -P -m sentinel.hook.push "$1" 2>&1)"
rc=$?
printf '%s\\n' "$output"

# If Sentinel did not print a verdicts summary, scan crashed BEFORE producing
# a verdict (ImportError, SyntaxError, broken package, wrong Python, etc.).
# Exit code alone is unreliable — Python returns 1 for ImportError, which
# warn mode would silence. Require the verdicts marker as proof-of-run.
if ! printf '%s' "$output" | grep -qE '(\\[Sentinel\\] verdicts:|"verdicts":)'; then
  echo "[Sentinel] scan did NOT produce verdicts — it CRASHED. Push BLOCKED for safety. Fix Sentinel or use SENTINEL_BYPASS=1." >&2
  exit 10
fi

# Sentinel internal error (try/except in scan CLI) — ALWAYS fail-closed.
if [ $rc -ge 10 ]; then
  echo "[Sentinel] scan returned internal-error (exit $rc). Push BLOCKED — fix Sentinel or use SENTINEL_BYPASS=1." >&2
  exit $rc
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
  printf '%s' "$PUSH_INPUT" | "$hook_backup" "$@"
  exit $?
fi
exit 0
"""


HOOK_SCRIPT = make_hook_script("block")
