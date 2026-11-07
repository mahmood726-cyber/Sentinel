"""P2-dashboard-stat-orphan: INFO on stat-card values that appear nowhere else in the HTML.

A `<div class="num">X%</div>` (or `Xx`, etc.) whose NORMALIZED value has
no equivalent reference anywhere else in the HTML file is a likely
stat-card-stale bug: narrative says one number, stat card says another,
update touched the narrative and missed the card.

Normalization collapses format variants to the same canonical key so
narrative cross-reference works:
  - '3.2x' / '3.2 x' / '3.2×' / '3.2-fold' / '3.2 fold' / '3.2 times' → '3.2@x'
  - '61.7%' / '61.7 percent' / '61.7 per cent'                        → '61.7@%'
  - '1.5K' / '1.5M' / '1.5B'                                          → '1.5@K' etc.

Triggering incident: shifaa 2026-04-16. Narrative '<strong>61.7% of the
HIC-LMIC trial gap</strong>' sat next to stat-card '<div class=\"num\">85%</div>
Gap explained by endowments'. Same concept, two numbers. 85% appeared
only in the one stat card.

Calibration refinement 2026-04-16 late: originally the rule flagged
'3.2x' in shifaa as orphan because the narrative said '3.2-fold'. Now
normalization collapses both to '3.2@x' and the rule no longer fires.

Excludes: node_modules, dist, build, vendor, coverage, .git, etc.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List, Optional, Set

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import HTML_EXCLUDE_DIRS, iter_repo_files
from sentinel.io.population import Population


ID = "P2-dashboard-stat-orphan"
SEVERITY = Severity.INFO
SOURCE = "lessons.md#portfolio-audit-patterns"
SCOPE = "repo"

# Population: PUBLISHED -- `git ls-files --cached`, i.e. the index. This
# is a DISCLOSURE rule: the harm requires the world to see the file. The
# index, not the commit, is the boundary -- a file becomes visible to
# this rule the moment it is `git add`ed, before any push. Migrated
# 2026-08-30; earlier counts used the same set, so they ARE comparable.
POPULATION = Population.PUBLISHED

# ReDoS guard: STAT_CARD_BLOCK_RE uses lazy `.*?` with DOTALL. On very
# large HTML files with unbalanced stat-card divs, backtracking could
# degrade. Skip files above this size rather than risk the scan budget.
MAX_FILE_BYTES = 5_000_000

# Match `<div class="num">VALUE</div>` where VALUE has a unit suffix.
# Accepts integer or decimal, with optional +/- sign.
# Units: % | x | × | K | M | B (case-insensitive).
STAT_CARD_RE = re.compile(
    r'<div\s+class\s*=\s*"[^"]*\bnum\b[^"]*"\s*>\s*'
    r'([+-]?\d+(?:\.\d+)?\s*(?:%|[xX]|×|[KMB]))\s*</div>',
    re.IGNORECASE,
)

# Match a standalone stat-card element (full block) so we can strip it
# from the text before scanning for narrative numbers.
STAT_CARD_BLOCK_RE = re.compile(
    r'<div\s+class\s*=\s*"[^"]*\bstat-card\b[^"]*"\s*>.*?</div>\s*</div>',
    re.IGNORECASE | re.DOTALL,
)

# Match any number token in narrative text with a unit hint.
# Order matters — longer suffixes first so 'fold' doesn't shadow 'x'.
NARRATIVE_NUM_RE = re.compile(
    r'([+-]?\d+(?:\.\d+)?)'
    r'\s*(-?\s*fold|percent|per\s*cent|times|%|×|[xX]\b|[KMB]\b)',
    re.IGNORECASE,
)


def _canonical_unit(raw: str) -> Optional[str]:
    u = raw.lower().strip().replace(" ", "").replace("-", "")
    if u in ("%", "percent", "percent.", "pct"):
        return "%"
    if u in ("x", "×", "fold", "times"):
        return "x"
    if u.upper() in ("K", "M", "B"):
        return u.upper()
    return None


def _normalize(number_str: str, unit_str: str) -> Optional[str]:
    """Return canonical key like '3.2@x' or '61.7@%' or None if unrecognized."""
    unit = _canonical_unit(unit_str)
    if unit is None:
        return None
    try:
        num = float(number_str)
    except ValueError:
        return None
    # %g drops trailing zeros but keeps decimal precision
    num_canonical = f"{num:g}"
    return f"{num_canonical}@{unit}"


def _normalize_stat_card(value_with_unit: str) -> Optional[str]:
    # Split trailing unit char(s) from the number
    m = re.match(r'^\s*([+-]?\d+(?:\.\d+)?)\s*(.*?)\s*$', value_with_unit)
    if not m:
        return None
    return _normalize(m.group(1), m.group(2))


def _extract_narrative_keys(text_without_cards: str) -> Set[str]:
    keys: Set[str] = set()
    for match in NARRATIVE_NUM_RE.finditer(text_without_cards):
        num, unit = match.group(1), match.group(2)
        key = _normalize(num, unit)
        if key is not None:
            keys.add(key)
    return keys


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []

    for path in _iter_html_files(ctx.repo_root):
        rel = path.relative_to(ctx.repo_root).as_posix()
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        cards = list(STAT_CARD_RE.finditer(text))
        if not cards:
            continue

        # Build narrative-only text (exclude stat-card blocks) so we don't
        # match the card's own number as its own reference.
        narrative_text = STAT_CARD_BLOCK_RE.sub(" ", text)
        narrative_keys = _extract_narrative_keys(narrative_text)

        seen_card_keys: Set[str] = set()
        for m in cards:
            raw_value = m.group(1).strip()
            key = _normalize_stat_card(raw_value)
            if key is None:
                continue
            if key in seen_card_keys:
                # Don't double-flag identical stat cards in same file.
                continue
            seen_card_keys.add(key)

            if key not in narrative_keys:
                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=SEVERITY,
                    repo=str(ctx.repo_root),
                    file=rel,
                    line=None,
                    detail=(
                        f"stat-card value {raw_value!r} (canonical {key}) "
                        f"has no narrative reference in {rel} — possibly "
                        "orphan after a partial update"
                    ),
                    fix_hint=(
                        f"search the file for {raw_value!r} or its synonyms "
                        "(e.g., '3.2x' ↔ '3.2-fold'); verify whether the "
                        "narrative uses a different number for the same metric"
                    ),
                    source=SOURCE,
                    timestamp=now,
                ))

    return verdicts


def _iter_html_files(root: Path) -> Iterator[Path]:
    return iter_repo_files(root, "*.html", HTML_EXCLUDE_DIRS, population=POPULATION)
