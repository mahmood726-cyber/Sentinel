"""Sentinel adapters — bridges Sentinel's rule engine into other tool surfaces.

Current adapters:
  - claude_agent_hooks: expose BLOCK-severity rules as Claude Agent SDK
    PreToolUse hooks, so violations are caught INSIDE an agent's execution
    loop rather than waiting for `git push` time.
"""
from __future__ import annotations
