"""Unit tests for sentinel.adapters.claude_agent_hooks.

These tests do NOT require claude-agent-sdk to be installed — the adapter
is designed to work off plain dicts (matching the SDK's TypedDict shape
at runtime). This keeps Sentinel's core test run SDK-free.

Test matrix:
  - Each content check (hardcoded path, placeholder HMAC, claude config,
    bash bypass) has a positive case (rule fires) and a negative case
    (rule doesn't fire).
  - Skip-file marker suppresses content checks.
  - Excluded paths are not scanned for hardcoded paths.
  - The hook callback returns SyncHookJSONOutput-shaped dicts with the
    right decision / hookSpecificOutput fields.
  - Unknown tool names are pass-through.
  - An internal exception in a check fails open, not closed.
"""
from __future__ import annotations

import asyncio

import pytest

from sentinel.adapters.claude_agent_hooks import (
    check_bash_bypass,
    check_claude_config_write,
    check_hardcoded_path,
    check_placeholder_hmac,
    sentinel_pretool_hook,
)


# --- helpers --------------------------------------------------------

def _run_hook(cb, tool_name: str, tool_input: dict) -> dict:
    """Invoke the async hook callback from sync test code."""
    hook_input = {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": "test_tool_use_1",
    }
    return asyncio.run(cb(hook_input, "test_tool_use_1", {"signal": None}))


def _is_block(response: dict) -> bool:
    return response.get("decision") == "block"


def _is_allow(response: dict) -> bool:
    return response.get("decision") != "block"


# --- check_hardcoded_path ------------------------------------------

def test_hardcoded_path_fires_on_c_users():
    f = check_hardcoded_path("app.py", 'OUT_DIR = "C:\\Users\\bob\\out"')
    assert f is not None
    assert f.rule_id == "P0-hardcoded-local-path"


def test_hardcoded_path_fires_on_unix_home():
    f = check_hardcoded_path("deploy.sh", 'cd /home/alice/project')
    assert f is not None


def test_hardcoded_path_clean_content_passes():
    f = check_hardcoded_path("app.py", 'OUT_DIR = Path("./out")')
    assert f is None


def test_hardcoded_path_respects_skip_file_marker():
    f = check_hardcoded_path(
        "app.py",
        '# sentinel:skip-file — this file intentionally references C:\\Users\\demo\n'
        'x = "C:\\Users\\demo\\file"',
    )
    assert f is None, "sentinel:skip-file must disable content checks"


def test_hardcoded_path_excluded_extensions_are_ignored():
    # .md is scannable — but .png is not in the scan extensions
    f = check_hardcoded_path("image.png", b"".decode() + 'C:\\Users\\x\\file')
    assert f is None, "non-code extensions must not be scanned"


def test_hardcoded_path_wiki_files_excluded():
    """wiki/ is excluded per YAML rule's exclude list."""
    f = check_hardcoded_path(
        "wiki/card_foo.md",
        'Project lives at C:\\Users\\bob\\projects\\foo',
    )
    assert f is None


def test_hardcoded_path_tests_dir_excluded():
    f = check_hardcoded_path(
        "tests/fixtures/fake_repo.py",
        'root = "C:\\Users\\bob\\repo"',
    )
    assert f is None


# --- check_placeholder_hmac ----------------------------------------

def test_placeholder_hmac_fires_on_sig_constant():
    content = '{"signature_placeholder": "SIG_RSA_SHA256_PLACEHOLDER"}'
    f = check_placeholder_hmac("bundle.json", content)
    assert f is not None
    assert f.rule_id == "P0-placeholder-hmac"


def test_placeholder_hmac_fires_on_todo_literal():
    content = 'bundle_signature = "TODO"'
    f = check_placeholder_hmac("cert.py", content)
    assert f is not None


def test_placeholder_hmac_clean_content_passes():
    content = 'bundle_signature = hmac.new(key, payload, sha256).hexdigest()'
    f = check_placeholder_hmac("cert.py", content)
    assert f is None


def test_placeholder_hmac_respects_skip_file_marker():
    content = (
        '# sentinel:skip-file\n'
        'signature_placeholder = "SIG_RSA_SHA256_TEST"\n'
    )
    f = check_placeholder_hmac("test_fixtures.py", content)
    assert f is None


# --- check_claude_config_write -------------------------------------

def test_claude_config_write_blocks_settings_json():
    f = check_claude_config_write(".claude/settings.json")
    assert f is not None
    assert f.rule_id == "P0-claude-config-committed"


def test_claude_config_write_blocks_nested():
    f = check_claude_config_write("subdir/.claude/agents/foo.md")
    assert f is not None


def test_claude_config_write_allows_local_settings():
    f = check_claude_config_write(".claude/settings.local.json")
    assert f is None, "settings.local.json is gitignored — allowed"


def test_claude_config_write_allows_unrelated_path():
    f = check_claude_config_write("src/main.py")
    assert f is None


# --- check_bash_bypass ---------------------------------------------

def test_bash_bypass_blocks_sentinel_bypass_var():
    f = check_bash_bypass("SENTINEL_BYPASS=1 git push")
    assert f is not None
    assert f.rule_id == "P0-sentinel-bypass-attempt"


def test_bash_bypass_blocks_with_spaces():
    f = check_bash_bypass("SENTINEL_BYPASS = 1 git push origin master")
    assert f is not None


def test_bash_bypass_allows_normal_git_push():
    f = check_bash_bypass("git push origin master")
    assert f is None


def test_bash_bypass_allows_unrelated_env_var():
    f = check_bash_bypass("DEBUG=1 python app.py")
    assert f is None


# --- hook callback end-to-end --------------------------------------

def test_hook_blocks_write_with_hardcoded_path():
    cb = sentinel_pretool_hook()
    resp = _run_hook(cb, "Write", {
        "file_path": "deploy.py",
        "content": 'ROOT = "C:\\Users\\bob\\project"',
    })
    assert _is_block(resp)
    assert "P0-hardcoded-local-path" in resp["reason"]
    assert resp["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_hook_blocks_edit_introducing_placeholder_hmac():
    cb = sentinel_pretool_hook()
    resp = _run_hook(cb, "Edit", {
        "file_path": "cert.py",
        "old_string": "bundle_signature = real_hmac()",
        "new_string": 'bundle_signature = "SIG_PLACEHOLDER"',
    })
    assert _is_block(resp)
    assert "P0-placeholder-hmac" in resp["reason"]


def test_hook_blocks_bash_bypass():
    cb = sentinel_pretool_hook()
    resp = _run_hook(cb, "Bash", {"command": "SENTINEL_BYPASS=1 git push"})
    assert _is_block(resp)
    assert "P0-sentinel-bypass-attempt" in resp["reason"]


def test_hook_allows_clean_write():
    cb = sentinel_pretool_hook()
    resp = _run_hook(cb, "Write", {
        "file_path": "app.py",
        "content": 'print("hello")',
    })
    assert _is_allow(resp)
    assert resp["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_hook_allows_clean_edit():
    cb = sentinel_pretool_hook()
    resp = _run_hook(cb, "Edit", {
        "file_path": "app.py",
        "old_string": "x = 1",
        "new_string": "x = 2",
    })
    assert _is_allow(resp)


def test_hook_allows_unrelated_bash():
    cb = sentinel_pretool_hook()
    resp = _run_hook(cb, "Bash", {"command": "pytest -xvs"})
    assert _is_allow(resp)


def test_hook_passes_through_unknown_tool():
    """An unknown tool name (e.g. Glob, MCP server tool) must not block —
    we only enforce on tools that can write code or run commands."""
    cb = sentinel_pretool_hook()
    resp = _run_hook(cb, "Glob", {"pattern": "**/*.py"})
    assert _is_allow(resp)


def test_hook_claude_config_write_blocked():
    cb = sentinel_pretool_hook()
    resp = _run_hook(cb, "Write", {
        "file_path": ".claude/settings.json",
        "content": '{"permissions": {"allow": ["*"]}}',
    })
    assert _is_block(resp)
    assert "P0-claude-config-committed" in resp["reason"]


def test_hook_claude_local_settings_allowed():
    cb = sentinel_pretool_hook()
    resp = _run_hook(cb, "Write", {
        "file_path": ".claude/settings.local.json",
        "content": '{"permissions": {"allow": ["*"]}}',
    })
    assert _is_allow(resp)


def test_hook_multiple_findings_all_surfaced():
    """Two separate violations in one Write — reason must mention both."""
    cb = sentinel_pretool_hook()
    resp = _run_hook(cb, "Write", {
        "file_path": ".claude/foo.py",  # triggers claude-config
        "content": 'x = "C:\\Users\\bob\\out"',  # also triggers hardcoded path
    })
    assert _is_block(resp)
    assert "P0-hardcoded-local-path" in resp["reason"]
    assert "P0-claude-config-committed" in resp["reason"]


def test_hook_fails_open_on_internal_exception(monkeypatch):
    """A bug in a check must not wedge the agent — log and allow."""
    def _boom(*args, **kwargs):
        raise RuntimeError("intentional test failure")

    # Patch the check registry indirectly by making the hardcoded-path
    # check raise. The hook-level try/except is what we're testing.
    monkeypatch.setattr(
        "sentinel.adapters.claude_agent_hooks.check_hardcoded_path",
        _boom,
    )
    cb = sentinel_pretool_hook()
    resp = _run_hook(cb, "Write", {
        "file_path": "app.py",
        "content": 'x = 1',
    })
    # Must be allow (fail-open), NOT block.
    assert _is_allow(resp)


# --- shape validation ----------------------------------------------

def test_block_response_has_modern_and_legacy_fields():
    """The SDK has evolved from `decision:"block"` to
    `permissionDecision:"deny"`. Support BOTH so the hook works across
    SDK versions."""
    cb = sentinel_pretool_hook()
    resp = _run_hook(cb, "Bash", {"command": "SENTINEL_BYPASS=1 git push"})
    # Legacy field
    assert resp["decision"] == "block"
    assert "reason" in resp
    # Modern field
    assert resp["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "permissionDecisionReason" in resp["hookSpecificOutput"]


def test_allow_response_shape():
    cb = sentinel_pretool_hook()
    resp = _run_hook(cb, "Write", {"file_path": "app.py", "content": "x=1"})
    assert resp.get("continue_") is True
    assert resp["hookSpecificOutput"]["permissionDecision"] == "allow"
