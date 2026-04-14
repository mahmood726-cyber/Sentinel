"""Writes findings into the target repo's review-findings.md / STUCK_FAILURES.md."""
from __future__ import annotations
from pathlib import Path
from typing import Sequence

from sentinel.core import Severity, Verdict


STUCK_HEADER = "# STUCK_FAILURES.md\n\n*Written by Sentinel — BLOCK-tier violations.*\n"
REVIEW_HEADER = "# review-findings.md\n\n*Written by Sentinel — WARN-tier findings.*\n"


def _format_verdict(v: Verdict) -> str:
    location = f"{v.file}:{v.line}" if v.file and v.line else v.file or "(repo-wide)"
    return (
        f"\n## [{v.severity.label}] {v.rule_id}\n"
        f"- **Location:** `{location}`\n"
        f"- **Detail:** {v.detail}\n"
        f"- **Fix hint:** {v.fix_hint}\n"
        f"- **Source:** {v.source}\n"
        f"- **When:** {v.timestamp.isoformat()}\n"
    )


def write_findings(repo_root: Path, verdicts: Sequence[Verdict]) -> None:
    blocks = [v for v in verdicts if v.severity == Severity.BLOCK]
    warns = [v for v in verdicts if v.severity == Severity.WARN]

    if blocks:
        path = repo_root / "STUCK_FAILURES.md"
        if not path.exists():
            path.write_text(STUCK_HEADER, encoding="utf-8")
        with path.open("a", encoding="utf-8") as f:
            for v in blocks:
                f.write(_format_verdict(v))

    if warns:
        path = repo_root / "review-findings.md"
        if not path.exists():
            path.write_text(REVIEW_HEADER, encoding="utf-8")
        with path.open("a", encoding="utf-8") as f:
            for v in warns:
                f.write(_format_verdict(v))
