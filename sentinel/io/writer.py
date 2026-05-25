"""Writes findings into the target repo.

Two parallel outputs per severity:
  - `.md`    human-readable append log (STUCK_FAILURES.md, sentinel-findings.md)
  - `.jsonl` machine-readable append log with same per-run semantics

JSONL is the canonical machine-readable source; downstream aggregators
(Overmind nightly verifier, dashboards, portfolio reports) should prefer
it over MD-regex parsing, which is fragile against heading format changes.

Filenames live in `sentinel.io.paths` — import from there; do not
duplicate literals. WARN output is `sentinel-findings.md` (not
`review-findings.md`) to avoid colliding with the `/review` skill.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Sequence

from sentinel.core import Severity, Verdict
from sentinel.io.paths import BLOCK_MD, BLOCK_JSONL, WARN_MD, WARN_JSONL


STUCK_HEADER = f"# {BLOCK_MD}\n\n*Written by Sentinel — BLOCK-tier violations.*\n"
REVIEW_HEADER = f"# {WARN_MD}\n\n*Written by Sentinel — WARN-tier findings.*\n"


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


def _append_jsonl(path: Path, verdicts: Sequence[Verdict]) -> None:
    with path.open("a", encoding="utf-8") as f:
        for v in verdicts:
            f.write(json.dumps(v.to_dict(), ensure_ascii=False) + "\n")


def write_findings(repo_root: Path, verdicts: Sequence[Verdict]) -> None:
    # JSONL is written first because downstream automation treats it as the
    # canonical machine-readable source. If a later Markdown append is
    # interrupted by a lock/crash, Overmind can still see the finding.
    blocks = [v for v in verdicts if v.severity == Severity.BLOCK]
    warns = [v for v in verdicts if v.severity == Severity.WARN]

    if blocks:
        _append_jsonl(repo_root / BLOCK_JSONL, blocks)
        md_path = repo_root / BLOCK_MD
        if not md_path.exists():
            md_path.write_text(STUCK_HEADER, encoding="utf-8")
        with md_path.open("a", encoding="utf-8") as f:
            for v in blocks:
                f.write(_format_verdict(v))

    if warns:
        _append_jsonl(repo_root / WARN_JSONL, warns)
        md_path = repo_root / WARN_MD
        if not md_path.exists():
            md_path.write_text(REVIEW_HEADER, encoding="utf-8")
        with md_path.open("a", encoding="utf-8") as f:
            for v in warns:
                f.write(_format_verdict(v))
