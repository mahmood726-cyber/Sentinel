from pathlib import Path
from datetime import datetime, timezone

import pytest

from sentinel.core import Severity, Verdict
from sentinel.io import writer


def _v(severity: Severity, rule_id: str) -> Verdict:
    return Verdict(
        rule_id=rule_id,
        severity=severity,
        repo="C:/repo",
        file="a.py",
        line=1,
        detail="d",
        fix_hint="fh",
        source="src.md",
        timestamp=datetime(2026, 4, 14, 0, 0, 0, tzinfo=timezone.utc),
    )


def test_block_jsonl_written_before_md_append_failure(tmp_path: Path, monkeypatch):
    """P1: JSONL is the machine source of truth and must be written first.

    If a crash or locked file interrupts the later Markdown append, Overmind
    can still aggregate the finding from JSONL.
    """
    original_open = Path.open

    def failing_md_append(self, *args, **kwargs):
        mode = args[0] if args else kwargs.get("mode", "r")
        if self.name == "STUCK_FAILURES.md" and "a" in mode:
            raise OSError("simulated markdown append failure")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing_md_append)

    with pytest.raises(OSError, match="markdown append failure"):
        writer.write_findings(tmp_path, [_v(Severity.BLOCK, "R-block")])

    jsonl_path = tmp_path / "STUCK_FAILURES.jsonl"
    assert jsonl_path.exists()
    assert '"rule_id": "R-block"' in jsonl_path.read_text(encoding="utf-8")
