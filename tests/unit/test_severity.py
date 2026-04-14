import pytest
from sentinel.core.severity import Severity


def test_severity_has_three_tiers():
    assert {s.name for s in Severity} == {"BLOCK", "WARN", "INFO"}


def test_severity_ordering_block_gt_warn_gt_info():
    assert Severity.BLOCK.rank > Severity.WARN.rank > Severity.INFO.rank


def test_severity_from_string_case_insensitive():
    assert Severity.from_string("block") == Severity.BLOCK
    assert Severity.from_string("BLOCK") == Severity.BLOCK
    assert Severity.from_string("Warn") == Severity.WARN


def test_severity_from_string_unknown_raises():
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.from_string("critical")
