"""Three-tier severity: BLOCK aborts, WARN logs, INFO dashboards only."""
from __future__ import annotations
from enum import Enum


class Severity(Enum):
    INFO = ("INFO", 0)
    WARN = ("WARN", 1)
    BLOCK = ("BLOCK", 2)

    def __init__(self, label: str, rank: int) -> None:
        self.label = label
        self.rank = rank

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        upper = value.upper()
        for member in cls:
            if member.label == upper:
                return member
        raise ValueError(f"unknown severity: {value!r} (expected BLOCK/WARN/INFO)")
