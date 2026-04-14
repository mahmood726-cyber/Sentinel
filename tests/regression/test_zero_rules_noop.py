"""Non-regression: Sentinel with zero rules exits 0 and writes nothing."""
from pathlib import Path
import pytest
from sentinel.core import RepoContext, ScanMode
from sentinel.io import write_findings
from sentinel.registry.registry import Registry, EmptyRegistryError


@pytest.mark.regression
def test_empty_rules_dir_raises_empty_registry(tmp_path: Path):
    root = tmp_path / "rules"
    (root / "yaml").mkdir(parents=True)
    (root / "plugins").mkdir(parents=True)
    with pytest.raises(EmptyRegistryError):
        Registry.from_dir(root)


@pytest.mark.regression
def test_zero_verdicts_writes_nothing(tmp_path: Path):
    write_findings(tmp_path, [])
    assert list(tmp_path.iterdir()) == []
