"""Uniform verdict record emitted by every rule, regardless of rule type."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sentinel.core.severity import Severity


@dataclass(frozen=True)
class Verdict:
    rule_id: str
    severity: Severity
    repo: str
    file: Optional[str]
    line: Optional[int]
    detail: str
    fix_hint: str
    source: str
    timestamp: datetime

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.label,
            "repo": self.repo,
            "file": self.file,
            "line": self.line,
            "detail": self.detail,
            "fix_hint": self.fix_hint,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
        }
