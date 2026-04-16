"""P2-dashboard-stat-orphan: INFO on stat-card values that appear nowhere else in the HTML.

A `<div class="num">X%</div>` (or `Xx`, etc.) whose value appears
NOWHERE ELSE in the surrounding HTML file is a likely stat-card-stale
bug: narrative says one number, stat card says another, update touched
the narrative and missed the card.

Triggering incident: shifaa 2026-04-16. Narrative "<strong>61.7% of the
HIC-LMIC trial gap</strong> is explained by covariate differences" sat
next to stat-card "<div class='num'>85%</div> Gap explained by endowments".
Same concept, two numbers. 85% appeared only in the one stat card — the
rule would have surfaced it.

Heuristic:
  - Find all `<div class="num">(value)</div>` where value ends in a unit
    suffix (%, x, K, M, B). Bare integers are skipped (too prone to
    prose false-positives like "42 countries").
  - For each stat-card value, count its occurrences in the full HTML
    body. If count == 1 (only the stat card itself), flag as INFO.
  - Legitimate unique KPIs will false-positive; INFO severity reflects
    this (never blocks, never warns loudly — surfaces for review).

Excludes node_modules, dist, build, vendor, coverage, .git, etc.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P2-dashboard-stat-orphan"
SEVERITY = Severity.INFO
SOURCE = "lessons.md#portfolio-audit-patterns"
SCOPE = "repo"

EXCLUDE_DIRS = {
    "node_modules", "dist", "build", "vendor", "coverage", ".git",
    ".pytest_cache", "__pycache__", "playwright-report", "test-results",
    "htmlcov",
}

# Match `<div class="num">VALUE</div>` where VALUE has a unit suffix.
# Accepts integer or decimal, with optional +/- sign.
STAT_CARD_RE = re.compile(
    r'<div\s+class\s*=\s*"[^"]*\bnum\b[^"]*"\s*>\s*'
    r'([+-]?\d+(?:\.\d+)?\s*[%xKMB])\s*</div>',
    re.IGNORECASE,
)


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []

    for path in _iter_html_files(ctx.repo_root):
        rel = path.relative_to(ctx.repo_root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Collect all stat-card values with their positions
        cards = [(m.group(1).strip(), m.start()) for m in STAT_CARD_RE.finditer(text)]
        if not cards:
            continue

        for value, _pos in cards:
            # Count total occurrences of this value in the whole file.
            # If only 1 -> orphan (appears only in the stat card itself).
            count = text.count(value)
            if count <= 1:
                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=SEVERITY,
                    repo=str(ctx.repo_root),
                    file=rel,
                    line=None,
                    detail=(
                        f"stat-card value {value!r} appears only once "
                        f"in {rel} — possibly orphan after a narrative update"
                    ),
                    fix_hint=(
                        f"search the file for {value!r}; verify whether the "
                        "narrative uses a different number for the same metric"
                    ),
                    source=SOURCE,
                    timestamp=now,
                ))

    return verdicts


def _iter_html_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*.html"):
        if not path.is_file():
            continue
        if any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        yield path
