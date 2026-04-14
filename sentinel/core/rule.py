"""Rule protocol — both YAML-backed and plugin-backed rules satisfy it."""
from __future__ import annotations
from typing import Protocol, Sequence, runtime_checkable

from sentinel.core.context import RepoContext
from sentinel.core.severity import Severity
from sentinel.core.verdict import Verdict


@runtime_checkable
class Rule(Protocol):
    """Every rule exposes these four attributes + check()."""

    id: str
    severity: Severity
    source: str
    scope: str  # "repo" or "portfolio"

    def check(self, ctx: RepoContext) -> Sequence[Verdict]:
        ...
