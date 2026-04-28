"""Canonical filenames Sentinel writes into scanned repos.

Centralized so that `yaml_loader.GLOBAL_EXCLUDES`, `writer.write_findings`,
and `.gitignore` all agree on the same names. Renaming here is a one-site
change.

WARN_MD is `sentinel-findings.md` (not `review-findings.md`) to avoid
collision with the `/review` multi-persona skill, which writes its output
to `review-findings.md`. Two tools writing to one file silently corrupts
both reports.
"""
from __future__ import annotations

BLOCK_MD = "STUCK_FAILURES.md"
BLOCK_JSONL = "STUCK_FAILURES.jsonl"
WARN_MD = "sentinel-findings.md"
WARN_JSONL = "sentinel-findings.jsonl"
SARIF_OUT = "sentinel-findings.sarif"

OUTPUT_FILENAMES = (BLOCK_MD, BLOCK_JSONL, WARN_MD, WARN_JSONL, SARIF_OUT)

# Legacy WARN output name (pre-rename). Repos that ran Sentinel before the
# rename may still have these files on disk; keep them in GLOBAL_EXCLUDES so
# they don't become a BLOCK cascade after upgrade. Also: the `/review` skill
# writes to review-findings.md, and that output should never be scanned by
# Sentinel's P0/P1 rules.
LEGACY_FILENAMES = ("review-findings.md", "review-findings.jsonl")


def global_exclude_patterns() -> tuple[str, ...]:
    """Glob patterns (root + nested) that exclude Sentinel's own output
    files from being scanned by Sentinel itself. Without these, every
    scan after the first produces a cascade of self-reference findings."""
    out: list[str] = []
    for name in OUTPUT_FILENAMES + LEGACY_FILENAMES:
        out.append(f"**/{name}")
    return tuple(out)
