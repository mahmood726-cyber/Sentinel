"""Runtime context passed to every rule's check() function."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional


class ScanMode(Enum):
    REPO = "repo"
    PORTFOLIO = "portfolio"


@dataclass(frozen=True)
class RepoContext:
    repo_root: Path
    mode: ScanMode
    project_index_root: Optional[Path] = None

    def __post_init__(self) -> None:
        if self.mode == ScanMode.PORTFOLIO and self.project_index_root is None:
            raise ValueError(
                "project_index_root required when mode=PORTFOLIO "
                "(need access to INDEX.md + manifest)"
            )

    def is_repo_scan(self) -> bool:
        return self.mode == ScanMode.REPO

    def is_portfolio_scan(self) -> bool:
        return self.mode == ScanMode.PORTFOLIO
