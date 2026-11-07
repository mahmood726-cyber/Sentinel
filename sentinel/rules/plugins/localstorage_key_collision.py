"""P0-localstorage-key-collision: BLOCK when 2+ dashboards share the same
rapid_meta_* localStorage key prefix.

Single-domain GitHub Pages sites share localStorage across all dashboards
hosted on the same origin. When two dashboards re-use the same key prefix
(via clone-heritage copy-paste — e.g. SPARSENTAN_IGAN cloned from
VOCLOSPORIN_LN inheriting `rapid_meta_anifrolumab_sle_v1_0`), opening one
after the other has the second one stomp the first's persisted state
(saved trial reviews, screening decisions, included/excluded selections).

This is a cross-file invariant — per-file scans miss it. The rule walks the
entire repo, builds {prefix: {files}}, and BLOCKs any prefix used by 2+
dashboards.

Triggering incident: localStorage audit 2026-04-29 found 18 prefix
collisions across 38 file-pairings; fixed via fix_localstorage_collisions.py
in rapidmeta-finerenone. Rule prevents regression.
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import HTML_EXCLUDE_DIRS, iter_repo_files
from sentinel.io.population import Population


ID = "P0-localstorage-key-collision"
SEVERITY = Severity.BLOCK
SOURCE = "lessons.md#localstorage-collision-2026-04-29"
SCOPE = "repo"

# Population: PRESENT -- tracked AND untracked-not-ignored. This is a
# CORRECTNESS rule: the defect it finds runs when someone runs the file,
# whether or not git is tracking it. Migrated 2026-08-30; counts from
# before that date were taken over the tracked set only and are NOT
# comparable with counts after it.
POPULATION = Population.PRESENT

MAX_FILE_BYTES = 10_000_000

# Match `rapid_meta_<token>` localStorage keys (alphanumeric+underscore tail).
# Strip optional version suffix (_vN_M) and theme suffix to get the canonical
# prefix that should be unique per dashboard.
KEY_RE = re.compile(r"rapid_meta_\w+")
SUFFIX_RE = re.compile(r"_(theme|v\d+_\d+)$")


def _canonical_prefix(key: str) -> str:
    return SUFFIX_RE.sub("", key)


def _line_of(text: str, offset: int) -> int:
    return text.count('\n', 0, offset) + 1


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []

    # First pass: build {prefix: {file: first_line_offset}}
    prefix_to_files: dict[str, dict[str, int]] = defaultdict(dict)

    for path in _iter_html_files(ctx.repo_root):
        rel = path.relative_to(ctx.repo_root).as_posix()
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for m in KEY_RE.finditer(text):
            prefix = _canonical_prefix(m.group(0))
            # Record first occurrence of this prefix in this file
            if rel not in prefix_to_files[prefix]:
                prefix_to_files[prefix][rel] = m.start()

    # Second pass: any prefix used by 2+ files (with DISTINCT basenames) =
    # collision. Mirror copies (e.g. e156-submission/assets/X = top-level X)
    # are intentional submission duplicates, not real collisions.
    for prefix, files in prefix_to_files.items():
        # Group by basename — collapse path mirrors of the same file
        from os.path import basename
        by_basename: dict[str, str] = {}
        for rel in files:
            bn = basename(rel)
            # Keep top-level path over nested submission mirrors
            if bn not in by_basename or '/' not in rel:
                by_basename[bn] = rel
        if len(by_basename) < 2:
            continue
        sorted_files = sorted([(rel, files[rel]) for rel in by_basename.values()])
        # Emit one BLOCK per file in the collision (so each file's commit
        # gets the verdict in its own scan), but don't double-count the
        # prefix in the message.
        for rel, offset in sorted_files:
            other_files = [f for f, _ in sorted_files if f != rel]
            text = (ctx.repo_root / rel).read_text(encoding='utf-8', errors='replace')
            line = _line_of(text, offset)
            verdicts.append(Verdict(
                rule_id=ID,
                severity=Severity.BLOCK,
                repo=str(ctx.repo_root),
                file=rel,
                line=line,
                detail=(
                    f"localStorage key prefix {prefix!r} is shared with "
                    f"{len(other_files)} other dashboard(s): {', '.join(other_files)}. "
                    f"Same-domain GitHub Pages will have these dashboards "
                    f"overwrite each other's persisted state."
                ),
                fix_hint=(
                    f"migrate this file's localStorage keys from {prefix!r} "
                    f"to a filename-derived prefix like "
                    f"'rapid_meta_{rel.replace('_REVIEW.html','').lower()}'. "
                    "Run scripts/fix_localstorage_collisions.py if available."
                ),
                source=SOURCE,
                timestamp=now,
            ))

    return verdicts


def _iter_html_files(root: Path) -> Iterator[Path]:
    return iter_repo_files(root, '*_REVIEW.html', HTML_EXCLUDE_DIRS, population=POPULATION)
