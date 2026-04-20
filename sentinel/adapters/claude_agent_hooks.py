"""Claude Agent SDK PreToolUse hook adapter for Sentinel.

Runs a subset of Sentinel's BLOCK-severity rules against PROPOSED tool-call
output — before the agent commits any change. Contrast with Sentinel's
standard pre-push model, which runs after files are already on disk.

Scope: intentionally small. Only rules that can decide from a single file's
proposed content + path, without a full repo scan. For portfolio-wide or
cross-file checks (registry drift, blueprint-implementation match), keep
the push-time hook — this adapter doesn't replace it.

Tool coverage:
  - Write: inspect `file_path` + `content`. Block hardcoded local paths,
    placeholder HMAC signatures, writes into .claude/ that would commit
    agent config.
  - Edit: inspect `file_path` + `new_string`. Same checks as Write; a
    hardcoded path introduced via Edit is the same bug as via Write.
  - Bash: inspect `command`. Block `SENTINEL_BYPASS=1 git push` attempts
    (and record them — per lessons.md#ROADMAP-note, the whole point of
    moving enforcement into the SDK loop is logging bypass attempts that
    the pre-push hook would quietly allow).

Fail-open on SDK absence: the claude-agent-sdk package is an OPTIONAL
dependency (users on older Claude Code without the SDK still want core
Sentinel). `sentinel_pretool_hook()` is importable even when the SDK is
not installed — the callback returns a plain dict matching the
SyncHookJSONOutput shape, which the SDK accepts at runtime without a
compile-time type dependency.

The SDK type aliases (PreToolUseHookInput, SyncHookJSONOutput) are
resolved at callback-time via a best-effort import; tests mock the
input as a plain dict / TypedDict-compatible dict, so no SDK install
is needed to unit-test the adapter.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Awaitable, Callable, Iterable

_log = logging.getLogger(__name__)


# =====================================================================
# Content-level checks (port of Sentinel rules that need only path + content)
# =====================================================================

# P0-hardcoded-local-path — copied from the YAML rule's pattern.
_HARDCODED_PATH = re.compile(
    r"(?i)("
    r"[A-Z]:[\\/](Users|projects|ProgramData|OneDrive)[\\/][^\s\"\\/]+"
    r"|"
    r"(?:^|(?<=[\s\"'(=:,]))/(?:Users|home)/[a-z_][\w-]*"
    r")"
)

# Paths Sentinel's YAML rule excludes from scanning. Keep in sync with
# P0-hardcoded-local-path.yaml's `exclude:` block.
_HARDCODED_PATH_EXCLUDED_SUBSTRINGS = (
    "sentinel/rules/",
    "docs/superpowers/specs/",
    "docs/superpowers/plans/",
    "docs/plans/",
    "truthcert1_work/",
    "docs/index.html",
    "wiki/",
    "data/nightly_reports/",
    "data/artifacts/",
    "data/real_project_smoke/",
    "data/baseline_probes/",
    # tests/fixtures and conftest are also excluded in the YAML rule,
    # but a PreToolUse on a test file creating a fixture path is fine.
    "tests/",
    "/tests/",
    "fixtures/",
    "conftest.py",
)

_HARDCODED_PATH_SCAN_EXTENSIONS = {
    ".html", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".css", ".py", ".json", ".yaml", ".yml", ".md", ".csv",
    ".tsv", ".txt", ".toml", ".ini", ".cfg", ".R", ".r",
    ".sh", ".bat", ".ps1",
}

# P0-placeholder-hmac — stubs shipped as real signatures.
_PLACEHOLDER_HMAC = re.compile(
    r'"signature_placeholder":\s*"SIG_[A-Z0-9_]+_?"'
    r"|signature.*=.*['\"]SIG_[A-Z0-9_]+_?['\"]"
    r"|bundle_signature.*=.*['\"](?:PLACEHOLDER|TODO|REPLACE_ME|STUB)['\"]",
    re.IGNORECASE,
)

# P0-claude-config-committed — writes into .claude/ that would commit
# agent config to a repo. Allows .claude/settings.local.json (gitignored).
_CLAUDE_CONFIG_DIR = re.compile(r"(?:^|[\\/])\.claude[\\/]")
_CLAUDE_LOCAL_SETTINGS = re.compile(r"\.claude[\\/]settings\.local\.json$")

# SENTINEL_BYPASS — the whole point of SDK-hook enforcement is to catch
# bypass attempts that pre-push would allow.
_BYPASS_PATTERN = re.compile(
    r"SENTINEL_BYPASS\s*=\s*1\b",
    re.IGNORECASE,
)

# sentinel:skip-file marker — if present in content, skip content checks
# (matches Sentinel's file-level scanner behavior).
_SKIP_FILE_MARKER = "sentinel:skip-file"


class Finding:
    """A single block-worthy rule violation. Equivalent to a Sentinel Verdict,
    but stripped to what a hook response needs to surface."""

    __slots__ = ("rule_id", "detail", "fix_hint")

    def __init__(self, rule_id: str, detail: str, fix_hint: str) -> None:
        self.rule_id = rule_id
        self.detail = detail
        self.fix_hint = fix_hint

    def as_reason(self) -> str:
        return f"[{self.rule_id}] {self.detail} — {self.fix_hint}"


def _path_is_excluded_from_hardcoded_scan(file_path: str) -> bool:
    """Is this file explicitly not scanned for hardcoded paths?

    Uses case-insensitive POSIX-style matching since agents emit both
    forward and back slashes. Mirrors P0-hardcoded-local-path.yaml's
    `exclude` list.
    """
    normalized = file_path.replace("\\", "/")
    return any(sub in normalized for sub in _HARDCODED_PATH_EXCLUDED_SUBSTRINGS)


def _path_has_scan_extension(file_path: str) -> bool:
    ext = Path(file_path).suffix.lower()
    return ext in _HARDCODED_PATH_SCAN_EXTENSIONS


def check_hardcoded_path(file_path: str, content: str) -> Finding | None:
    """P0-hardcoded-local-path port: BLOCK absolute `C:\\Users\\...` or
    `/home/<user>/...` paths in shipped code."""
    if _SKIP_FILE_MARKER in content:
        return None
    if not _path_has_scan_extension(file_path):
        return None
    if _path_is_excluded_from_hardcoded_scan(file_path):
        return None
    m = _HARDCODED_PATH.search(content)
    if not m:
        return None
    return Finding(
        rule_id="P0-hardcoded-local-path",
        detail=f"hardcoded local path in proposed content: {m.group(0)!r}",
        fix_hint=(
            "Replace with a relative path, config-driven root, or "
            "environment variable. Dev-environment paths must not land "
            "in shipped code (lessons.md#code-quality)."
        ),
    )


def check_placeholder_hmac(file_path: str, content: str) -> Finding | None:
    """P0-placeholder-hmac port: BLOCK placeholder signature strings that
    claim signed-ness without providing it."""
    if _SKIP_FILE_MARKER in content:
        return None
    m = _PLACEHOLDER_HMAC.search(content)
    if not m:
        return None
    return Finding(
        rule_id="P0-placeholder-hmac",
        detail=f"placeholder signature in proposed content: {m.group(0)!r}",
        fix_hint=(
            "Placeholder HMAC strings are a security bug, not a TODO. "
            "Wire a real signer (see overmind.verification.signers) or "
            "remove the claim entirely (lessons.md#cryptography--signing)."
        ),
    )


def check_claude_config_write(file_path: str) -> Finding | None:
    """P0-claude-config-committed port: BLOCK writes into a repo's .claude/
    directory that would commit agent configuration. Personal settings
    belong in `.claude/settings.local.json` (gitignored) — block everything
    else."""
    normalized = file_path.replace("\\", "/")
    if not _CLAUDE_CONFIG_DIR.search(normalized):
        return None
    # Allow the gitignored local-settings path explicitly.
    if _CLAUDE_LOCAL_SETTINGS.search(normalized):
        return None
    return Finding(
        rule_id="P0-claude-config-committed",
        detail=f"write into .claude/ directory: {file_path}",
        fix_hint=(
            "Repo-tracked .claude/ files commit personal agent config. "
            "Use .claude/settings.local.json (gitignored) for per-user "
            "settings, or add an explicit `.claude/` .gitignore entry."
        ),
    )


def check_bash_bypass(command: str) -> Finding | None:
    """SENTINEL_BYPASS detector: BLOCK attempts to bypass Sentinel's
    pre-push hook via the bypass env var.

    Rationale: the bypass exists for genuine emergencies (release-cut
    deadlines), but it's logged to ~/.sentinel-logs/bypass.log. An agent
    reaching for it is almost always trying to silence a real rule
    violation — block inside the SDK loop, where the agent can still
    diagnose and fix the underlying issue."""
    if _BYPASS_PATTERN.search(command):
        return Finding(
            rule_id="P0-sentinel-bypass-attempt",
            detail=f"agent attempted Sentinel bypass in bash: {command!r}",
            fix_hint=(
                "Do not use SENTINEL_BYPASS=1 to silence rule violations. "
                "Fix the underlying issue or add a sentinel:skip-file marker "
                "if the rule is genuinely false-positive on this file."
            ),
        )
    return None


# =====================================================================
# Hook dispatch
# =====================================================================

def _check_write_like(file_path: str, content: str) -> list[Finding]:
    """Run all content-level checks for a Write or Edit operation."""
    findings: list[Finding] = []
    for check in (check_hardcoded_path, check_placeholder_hmac):
        f = check(file_path, content)
        if f is not None:
            findings.append(f)
    f = check_claude_config_write(file_path)
    if f is not None:
        findings.append(f)
    return findings


def _evaluate_hook_input(hook_input: dict[str, Any]) -> list[Finding]:
    """Dispatch to the right check set based on tool_name.

    Accepts a plain dict (PreToolUseHookInput is a TypedDict) so tests
    don't require the SDK to be installed.
    """
    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {}) or {}

    if tool_name == "Write":
        return _check_write_like(
            file_path=tool_input.get("file_path", ""),
            content=tool_input.get("content", ""),
        )
    if tool_name == "Edit":
        # Checks run against the NEW content the edit introduces; the old
        # string isn't relevant — if it had a violation, the file was
        # already broken, and that's the push-time hook's job.
        return _check_write_like(
            file_path=tool_input.get("file_path", ""),
            content=tool_input.get("new_string", ""),
        )
    if tool_name == "Bash":
        f = check_bash_bypass(tool_input.get("command", ""))
        return [f] if f is not None else []
    # Unknown tool: no-op (fail-open — the SDK loop has many tools we
    # don't care about; blocking unrecognized tools would be noisy).
    return []


def _block_response(findings: Iterable[Finding]) -> dict[str, Any]:
    """Build a SyncHookJSONOutput dict that the SDK interprets as a
    PreToolUse block. Uses permissionDecision="deny" (the modern path)
    as well as decision="block" + reason for older SDK versions."""
    findings = list(findings)
    reason = "\n".join(f.as_reason() for f in findings)
    return {
        "decision": "block",
        "reason": reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
    }


def _allow_response() -> dict[str, Any]:
    """Pass-through response. continue_=True is the default, so an empty
    dict is sufficient — but returning a populated shape makes the
    agent-SDK-facing contract explicit for debugging."""
    return {
        "continue_": True,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
        },
    }


# Public callback type. We spell it out rather than importing
# claude_agent_sdk.types.HookCallback so the module stays importable
# without the SDK installed (tests run SDK-less).
SentinelHookCallback = Callable[..., Awaitable[dict[str, Any]]]


def sentinel_pretool_hook() -> SentinelHookCallback:
    """Return a PreToolUse hook callback that enforces Sentinel BLOCK rules
    against proposed tool-call content.

    Usage (inside a Claude Agent SDK client):

        from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions, HookMatcher
        from sentinel.adapters.claude_agent_hooks import sentinel_pretool_hook

        options = ClaudeAgentOptions(
            hooks={
                "PreToolUse": [HookMatcher(
                    matcher="Write|Edit|Bash",
                    hooks=[sentinel_pretool_hook()],
                )],
            },
        )

    The returned callback is async (the SDK's contract) but runs the
    underlying checks synchronously — they're all regex-on-string, no IO.
    """

    async def _callback(
        input_data: dict[str, Any],
        tool_use_id: str | None,
        context: dict[str, Any] | Any,
    ) -> dict[str, Any]:
        try:
            findings = _evaluate_hook_input(input_data)
        except Exception as e:
            # Fail open — a buggy rule must not block legitimate tool calls.
            # Log loudly so the bug surfaces, but don't wedge the agent.
            _log.exception("sentinel pretool hook raised: %s", e)
            return _allow_response()

        if findings:
            _log.warning(
                "sentinel blocked tool call: %s",
                "; ".join(f.as_reason() for f in findings),
            )
            return _block_response(findings)
        return _allow_response()

    return _callback
