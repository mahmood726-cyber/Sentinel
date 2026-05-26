"""Tests for the pre-push hook payload's --diff-by-default behavior.

The hook script (sentinel/hook/payload.py) was updated to invoke
`sentinel scan --diff --base-ref <auto>` by default instead of a full-
tree scan. This cuts pre-push from ~2 minutes on a 3000-file repo to
~1 second on a typical small-PR push. Operator can force the old
full-tree behavior via `SENTINEL_DIFF_BASE=full`.

These tests verify the SHELL-SCRIPT-FRAGMENT shape only — actually
exercising the hook end-to-end requires a real git repo with hooks
enabled, which test_hook_installer covers separately.
"""
from __future__ import annotations

import pytest

from sentinel.hook.payload import make_hook_script


def test_hook_uses_diff_mode_by_default():
    """Without SENTINEL_DIFF_BASE set, the hook auto-detects a base ref
    from origin/HEAD → origin/main → origin/master → HEAD~1."""
    script = make_hook_script("block")
    # The auto-detect loop checks these refs in order.
    assert "for candidate in origin/HEAD origin/main origin/master HEAD~1" in script
    # When auto-detect succeeds, the scan is invoked with --diff --base-ref.
    assert 'SCAN_ARGS="--diff --base-ref $candidate"' in script


def test_hook_honors_explicit_diff_base_env():
    """Setting SENTINEL_DIFF_BASE=<ref> overrides auto-detection."""
    script = make_hook_script("block")
    assert 'DIFF_BASE="${SENTINEL_DIFF_BASE:-}"' in script
    # The 'elif -n DIFF_BASE' branch uses the explicit value.
    assert 'SCAN_ARGS="--diff --base-ref $DIFF_BASE"' in script


def test_hook_supports_full_scan_opt_out():
    """SENTINEL_DIFF_BASE=full reverts to whole-tree scan (V1 behavior)."""
    script = make_hook_script("block")
    assert 'if [ "$DIFF_BASE" = "full" ]; then' in script
    # When full mode: SCAN_ARGS is empty (no --diff/--base-ref flags).
    assert '  SCAN_ARGS=""' in script


def test_hook_scan_invocation_uses_scan_args():
    """The python invocation must pass $SCAN_ARGS unquoted so empty-string
    expansion in full mode doesn't pass a literal '' to sentinel scan."""
    script = make_hook_script("block")
    # Unquoted $SCAN_ARGS lets shell word-splitting expand to either
    # "--diff --base-ref X" (3 args) or "" (0 args).
    assert 'sentinel scan --repo "$REPO_TOPLEVEL" $SCAN_ARGS' in script


def test_hook_falls_back_to_full_scan_when_no_base_resolves():
    """If none of the candidate base refs exist (e.g. fresh local-only
    repo), SCAN_ARGS defaults to empty via parameter expansion → full scan.
    'No diff base' must never silently bypass the scan."""
    script = make_hook_script("block")
    # The post-loop default: SCAN_ARGS="${SCAN_ARGS:-}" ensures the
    # variable is defined and empty if the loop didn't break.
    assert 'SCAN_ARGS="${SCAN_ARGS:-}"' in script


def test_hook_marker_still_present():
    """The SENTINEL_MARKER banner must remain intact so the installer can
    detect Sentinel-installed hooks vs. user hooks."""
    from sentinel.hook.payload import SENTINEL_MARKER
    script = make_hook_script("block")
    assert SENTINEL_MARKER in script


def test_hook_block_and_warn_modes_both_supported():
    """The mode flag still bakes into the MODE= line."""
    block_script = make_hook_script("block")
    warn_script = make_hook_script("warn")
    assert 'MODE="${SENTINEL_MODE:-block}"' in block_script
    assert 'MODE="${SENTINEL_MODE:-warn}"' in warn_script


def test_hook_invalid_mode_raises():
    with pytest.raises(ValueError):
        make_hook_script("invalid-mode")
