"""P2-10: triage CLI must refuse to overwrite canonical aggregation files."""
from __future__ import annotations

from pathlib import Path

from sentinel.cli.triage import _reject_canonical_output
from sentinel.io.paths import OUTPUT_FILENAMES


def test_rejects_each_canonical_filename(tmp_path: Path):
    for name in OUTPUT_FILENAMES:
        err = _reject_canonical_output(tmp_path / name)
        assert err is not None
        assert name in err


def test_allows_non_canonical_path(tmp_path: Path):
    assert _reject_canonical_output(tmp_path / "triage-out.json") is None


def test_none_out_is_allowed():
    assert _reject_canonical_output(None) is None


def test_rejects_canonical_in_subdir(tmp_path: Path):
    # basename match — even nested, the canonical name is refused.
    nested = tmp_path / "sub" / "STUCK_FAILURES.jsonl"
    assert _reject_canonical_output(nested) is not None
