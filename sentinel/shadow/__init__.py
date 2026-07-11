"""Shadow-mode matchers — run ALONGSIDE the enforcing regex rules, never
instead of them.

Nothing in this package is loaded by `sentinel.registry.Registry` (it lives
outside `sentinel/rules/`), so importing/using it CANNOT change what a
`sentinel scan` blocks. It exists purely to measure whether an AST-based
matcher would catch what the regex rule catches — plus the regex-evasion
cases the benchmark flagged — before anyone decides to promote it.

Benchmark item #5 / ★3 (2026-07-11): "42/64 rules are evadable regex …
port the hot rules to AST … in SHADOW MODE ONLY."
"""
from __future__ import annotations

from sentinel.shadow.ast_matchers import (
    ShadowFinding,
    ast_insecure_deserialization,
    ast_leaked_secret,
    ast_unsafe_eval_exec,
)

__all__ = [
    "ShadowFinding",
    "ast_unsafe_eval_exec",
    "ast_leaked_secret",
    "ast_insecure_deserialization",
]
