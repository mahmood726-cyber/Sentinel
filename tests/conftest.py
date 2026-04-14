"""Shared pytest fixtures."""
from pathlib import Path
import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    """Absolute path to tests/fixtures/."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    """An empty tmp directory that behaves like a repo root."""
    return tmp_path
