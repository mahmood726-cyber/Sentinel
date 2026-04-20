"""SDK-dependent shape-conformance test for claude_agent_hooks.

Only runs when claude-agent-sdk is installed (it's an optional dep).
Verifies that the dicts `sentinel_pretool_hook()` produces structurally
match the SDK's TypedDict shapes — catches drift when the SDK bumps
its protocol (e.g. renamed fields, new required keys).

This is a CONTRACT test: it doesn't test behavior, only shape.
"""
from __future__ import annotations

import asyncio

import pytest

sdk_types = pytest.importorskip(
    "claude_agent_sdk.types",
    reason="claude-agent-sdk not installed — shape-conformance test skipped",
)

from sentinel.adapters.claude_agent_hooks import sentinel_pretool_hook  # noqa: E402


def _run(cb, hook_input):
    return asyncio.run(cb(hook_input, "test_id", {"signal": None}))


def test_block_response_has_all_syncHookJSONOutput_known_fields():
    """Every key in our block response is a field the SDK recognizes.

    We don't check every SDK field is set (most are NotRequired), only
    that nothing we emit is unknown to the TypedDict."""
    from claude_agent_sdk.types import SyncHookJSONOutput

    cb = sentinel_pretool_hook()
    resp = _run(cb, {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "SENTINEL_BYPASS=1 git push"},
        "tool_use_id": "t1",
    })

    # Python TypedDicts don't enforce at runtime, but we can inspect
    # annotations to verify our keys are valid.
    known_fields = set(SyncHookJSONOutput.__annotations__.keys())
    for key in resp.keys():
        assert key in known_fields, (
            f"block response key {key!r} not in SyncHookJSONOutput; "
            f"known: {sorted(known_fields)}"
        )


def test_allow_response_has_all_syncHookJSONOutput_known_fields():
    from claude_agent_sdk.types import SyncHookJSONOutput

    cb = sentinel_pretool_hook()
    resp = _run(cb, {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "app.py", "content": "x = 1"},
        "tool_use_id": "t2",
    })

    known_fields = set(SyncHookJSONOutput.__annotations__.keys())
    for key in resp.keys():
        assert key in known_fields, (
            f"allow response key {key!r} not in SyncHookJSONOutput; "
            f"known: {sorted(known_fields)}"
        )


def test_hook_specific_output_uses_known_fields():
    from claude_agent_sdk.types import PreToolUseHookSpecificOutput

    cb = sentinel_pretool_hook()
    resp = _run(cb, {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "SENTINEL_BYPASS=1 git push"},
        "tool_use_id": "t3",
    })

    hso = resp["hookSpecificOutput"]
    known_fields = set(PreToolUseHookSpecificOutput.__annotations__.keys())
    for key in hso.keys():
        assert key in known_fields, (
            f"hookSpecificOutput key {key!r} not in "
            f"PreToolUseHookSpecificOutput; known: {sorted(known_fields)}"
        )
    # These are the semantic fields we rely on
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] in ("allow", "deny", "ask")


def test_callback_is_awaitable():
    """The SDK requires HookCallback to be an async callable. Our factory
    must return one — not a plain function."""
    cb = sentinel_pretool_hook()
    result = cb(
        {"hook_event_name": "PreToolUse", "tool_name": "X", "tool_input": {}, "tool_use_id": "x"},
        "x",
        {"signal": None},
    )
    assert asyncio.iscoroutine(result), "hook callback must be an async coroutine"
    # Close the unawaited coroutine to silence RuntimeWarning. Review P2-2.
    result.close()
