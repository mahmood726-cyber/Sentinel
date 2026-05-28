"""P0-citation-resolution: BLOCK capsule DOIs that an out-of-band resolver
checked against doi.org and found NOT to resolve.

E156 Assurance Standard "Made-up citations" risk class, Phase 2. The companion
rule `citation_cascade` checks only DOI *shape* — a structurally valid but
fabricated DOI (10.9999/invented.study) passes it clean. The standard says a
made-up citation is an automatic fail; this rule enforces that.

Resolution is slow and network-bound, so it does NOT happen here. The resolver
(E156 scripts/assurance/doi_resolver.py) runs out-of-band, resolves DOIs against
doi.org, and writes a committed `doi-cache.json` at the repo root:

    { "10.9999/invented": {"status": "unresolved", "http_status": 404, "checked_at": "..."} }

This rule is OFFLINE: it reads only that cache and BLOCKs any well-formed DOI
in a capsule doc whose cached status == "unresolved". It makes no network call.

FALSE-POSITIVE DISCIPLINE (per the 2026-05-28 portfolio FP audit):
  - No cache, or no "unresolved" entries -> ZERO findings. The rule is inert on
    every repo that hasn't run the resolver, so it cannot regress existing
    pushes.
  - Only well-formed DOIs are considered (malformed ones are citation_cascade's
    job); DOIs the resolver couldn't reach are recorded "unknown" and never
    block — honest under-claiming is the safer error.
  - Files carrying `sentinel:skip-file` (negative-test fixtures, vendored
    copies) are skipped, mirroring the resolver.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.rules.plugins.citation_cascade import (
    DOI_PREFIX_RE,
    VALID_DOI_RE,
    _looks_like_attempted_doi,
    _iter_doc_files,
    _line_of,
)


ID = "P0-citation-resolution"
SEVERITY = Severity.BLOCK
SOURCE = "F:\\e156\\docs\\assurance-standard.md#1-citation-verification"
SCOPE = "repo"

CACHE_NAME = "doi-cache.json"
SKIP_MARKER = "sentinel:skip-file"
MAX_FILE_BYTES = 5_000_000


def _load_unresolved(cache_path: Path) -> dict:
    """Return {doi: record} for cache entries with status 'unresolved'."""
    if not cache_path.is_file():
        return {}
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        doi: rec
        for doi, rec in data.items()
        if isinstance(rec, dict) and rec.get("status") == "unresolved"
    }


def check(ctx: RepoContext) -> List[Verdict]:
    root = ctx.repo_root
    unresolved = _load_unresolved(root / CACHE_NAME)
    if not unresolved:
        return []

    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    for path in _iter_doc_files(root):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if SKIP_MARKER in text:
            continue
        rel = path.relative_to(root).as_posix()
        seen: set[str] = set()
        for m in DOI_PREFIX_RE.finditer(text):
            cand = m.group(1).strip(".,)]\"'").rstrip(".")
            if not _looks_like_attempted_doi(cand):
                continue
            if not VALID_DOI_RE.match(cand):
                continue  # malformed shape is citation_cascade's job
            if cand not in unresolved or cand in seen:
                continue
            seen.add(cand)
            rec = unresolved[cand]
            verdicts.append(Verdict(
                rule_id=ID,
                severity=Severity.BLOCK,
                repo=str(root),
                file=rel,
                line=_line_of(text, m.start()),
                detail=(
                    f"DOI {cand!r} did not resolve against doi.org "
                    f"(HTTP {rec.get('http_status')}, checked {rec.get('checked_at')}) "
                    f"— likely fabricated or mistyped. Per the Assurance Standard, "
                    f"a made-up citation is an automatic fail."
                ),
                fix_hint=(
                    "verify the DOI on doi.org / crossref.org; if no real DOI "
                    "exists, remove the reference. If doi.org was transiently "
                    "unavailable, re-run scripts/assurance/doi_resolver.py --force "
                    "to refresh doi-cache.json."
                ),
                source=SOURCE,
                timestamp=now,
            ))
    return verdicts
