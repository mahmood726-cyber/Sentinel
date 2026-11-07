"""P0-rapidmeta-data-integrity: BLOCK on silent-shadowing data bugs in
RapidMeta-style dashboards (*_REVIEW.html).

These bugs are all variants of "two fields with the same key in a JS object
literal — last one silently wins, masking real data". They surface as
wrong-trial labels in screening, lost trial pooling, or corrupted PICO/effect
estimates. They were caught manually after-the-fact in:

  - PEGCETACOPLAN_GA_REVIEW.html (commit 00a4428): OAKS and DERBY had their
    NCT IDs swapped, both keyed as 'OAKS' in nctAcronyms; a third stale
    realData entry under the duplicate NCT silently shadowed the first
    DERBY-mislabeled record. Also a `pmid: 'X', pmid: 'X'` duplicate.

This rule catches them before they ship.

Detected patterns:
  CRITICAL (BLOCK):
    1. Duplicate NCT key in realData (later entries shadow earlier).
    2. nctAcronyms map: same acronym mapped to >=2 NCTs.
    3. Duplicate top-level field within a single trial entry header
       (e.g. `pmid: 'X', pmid: 'X'`).

  WARN:
    4. NCT in realData with a `name:` field that differs from the
       nctAcronyms map's acronym for that same NCT.

Heuristics deliberately conservative — only fire when the file has a
recognizable RapidMeta `realData: { ... }` block.

Triggering incident: PEGCETACOPLAN_GA OAKS/DERBY swap (2026-04-28).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import HTML_EXCLUDE_DIRS, iter_repo_files
from sentinel.io.population import Population


ID = "P0-rapidmeta-data-integrity"
SEVERITY = Severity.BLOCK
SOURCE = "lessons.md#data-integrity:pegcetacoplan-oaks-derby-swap-2026-04-28"
SCOPE = "repo"

# Population: PRESENT -- tracked AND untracked-not-ignored. This is a
# CORRECTNESS rule: the defect it finds runs when someone runs the file,
# whether or not git is tracking it. Migrated 2026-08-30; counts from
# before that date were taken over the tracked set only and are NOT
# comparable with counts after it.
POPULATION = Population.PRESENT

MAX_FILE_BYTES = 10_000_000  # ReDoS / scan-budget guard

# realData block start. Permissive — `realData = {`, `realData: {`, etc.
REALDATA_RE = re.compile(r"\brealData\b\s*[:=]\s*\{")
NCT_KEY_RE = re.compile(r"'(NCT\d{8})'\s*:\s*\{")

# nctAcronyms map. Match the full {…} so we can parse k:v pairs inside.
NCTACR_RE = re.compile(r"\bnctAcronyms\b\s*[:=]\s*\{([^}]*)\}")
NCTACR_KV_RE = re.compile(r"'(NCT\d{8})'\s*:\s*'([^']*)'")

# Top-level entry name lookup
NAME_RE = re.compile(r"\bname\s*:\s*'([^']*)'")

# Top-level entry field assignments. Used to spot duplicate keys inside
# the FIRST line/header of an entry (before nested arrays start).
FIELD_RE = re.compile(r"\b(\w+)\s*:\s*[\'\[\{\d\-tfnu]")

# Whitelist: only flag duplicates of these structural fields. Anything
# else might be a legitimate property of nested objects we couldn't fully
# slice off, so we stay conservative.
TOP_LEVEL_FIELDS = frozenset({
    'name', 'pmid', 'phase', 'year', 'tE', 'tN', 'cE', 'cN',
    'group', 'publishedHR', 'hrLCI', 'hrUCI', 'snippet',
    'sourceUrl', 'ctgovUrl',
})


def _find_block_end(text: str, start_brace: int) -> int:
    """Return the offset of the `}` that closes the `{` at start_brace.
    Returns -1 if unbalanced or runaway."""
    depth = 0
    started = False
    limit = min(len(text), start_brace + 1_000_000)
    for j in range(start_brace, limit):
        c = text[j]
        if c == '{':
            depth += 1
            started = True
        elif c == '}':
            depth -= 1
            if started and depth == 0:
                return j
    return -1


def _line_of(text: str, offset: int) -> int:
    return text.count('\n', 0, offset) + 1


def _extract_realdata_entries(text: str):
    """Yield (nct, header) for each top-level NCT key in realData. The
    header is the entry's prefix BEFORE its first nested array (allOutcomes,
    evidence) or its closing brace - whichever comes first."""
    m = REALDATA_RE.search(text)
    if not m:
        return
    brace_open = m.end() - 1  # the `{` itself
    block_end = _find_block_end(text, brace_open)
    if block_end < 0:
        return
    block = text[brace_open:block_end + 1]
    block_offset = brace_open

    for km in NCT_KEY_RE.finditer(block):
        nct = km.group(1)
        entry_brace = block.find('{', km.end() - 1)  # opening { of the entry
        entry_end = _find_block_end(block, entry_brace)
        if entry_end < 0:
            continue
        body = block[entry_brace:entry_end + 1]
        # Strip nested arrays so duplicate-field detection only sees the
        # entry header, not properties of inner objects.
        cuts = []
        for marker in ('allOutcomes:', 'evidence:', 'rob:'):
            idx = body.find(marker)
            if idx > 0:
                cuts.append(idx)
        header = body[:min(cuts)] if cuts else body
        # Absolute offset for line reporting
        abs_offset = block_offset + km.start()
        yield nct, header, abs_offset


def _check_one_file(text: str, rel: str, now: datetime) -> List[Verdict]:
    verdicts: List[Verdict] = []
    if not REALDATA_RE.search(text):
        return verdicts

    entries = list(_extract_realdata_entries(text))
    if not entries:
        return verdicts

    # 1. Duplicate NCT keys in realData
    seen: dict[str, int] = {}
    for nct, _, abs_offset in entries:
        if nct in seen:
            verdicts.append(Verdict(
                rule_id=ID,
                severity=Severity.BLOCK,
                repo=None,  # filled in by caller
                file=rel,
                line=_line_of(text, abs_offset),
                detail=(
                    f"realData has duplicate NCT key {nct!r}; later entries "
                    f"silently shadow earlier ones via JS object-literal dedup"
                ),
                fix_hint=(
                    "remove the duplicate entry, or use distinct NCT keys; "
                    "verify each entry's `name:` field matches its NCT on "
                    "ClinicalTrials.gov before deleting either"
                ),
                source=SOURCE,
                timestamp=now,
            ))
        seen[nct] = abs_offset

    # 2. nctAcronyms acronym collision (same acronym -> multiple NCTs)
    acr_match = NCTACR_RE.search(text)
    if acr_match:
        rev: dict[str, list[str]] = {}
        for kv in NCTACR_KV_RE.finditer(acr_match.group(1)):
            rev.setdefault(kv.group(2), []).append(kv.group(1))
        for acronym, ncts in rev.items():
            if len(ncts) > 1:
                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=Severity.BLOCK,
                    repo=None,
                    file=rel,
                    line=_line_of(text, acr_match.start()),
                    detail=(
                        f"nctAcronyms maps acronym {acronym!r} to "
                        f"{len(ncts)} NCTs ({', '.join(ncts)}); each NCT "
                        f"must have a unique acronym or screening links lead "
                        f"users to the wrong trial on CT.gov"
                    ),
                    fix_hint=(
                        "verify each NCT against ClinicalTrials.gov and assign "
                        "the canonical acronym; if both trials really share an "
                        "acronym (e.g. companion trials), suffix one (e.g. "
                        "'OAKS', 'OAKS-2')"
                    ),
                    source=SOURCE,
                    timestamp=now,
                ))

    # 4. WARN: NCT in realData with a name that doesn't match nctAcronyms
    #    (run before #3 so duplicate-field reports come last for readability)
    if acr_match:
        acr_map: dict[str, str] = {}
        for kv in NCTACR_KV_RE.finditer(acr_match.group(1)):
            acr_map[kv.group(1)] = kv.group(2)
        for nct, header, abs_offset in entries:
            nm = NAME_RE.search(header)
            if not nm:
                continue
            name = nm.group(1)
            acr = acr_map.get(nct)
            if acr is None: continue
            # Allow descriptive-suffix style (acronym is "NAME (drug-A vs drug-B)").
            # Only flag when name and acronym share neither a prefix nor each other.
            n_up, a_up = name.upper().strip(), acr.upper().strip()
            if n_up == a_up: continue
            if a_up.startswith(n_up) or n_up.startswith(a_up): continue
            verdicts.append(Verdict(
                    rule_id=ID,
                    severity=Severity.WARN,
                    repo=None,
                    file=rel,
                    line=_line_of(text, abs_offset),
                    detail=(
                        f"NCT {nct} has realData name {name!r} but "
                        f"nctAcronyms says {acr!r}"
                    ),
                    fix_hint=(
                        f"verify against ClinicalTrials.gov which acronym is "
                        f"correct for {nct}; align both maps to that ground truth"
                    ),
                    source=SOURCE,
                    timestamp=now,
                ))

    # 3. Duplicate top-level fields in entry headers
    for nct, header, abs_offset in entries:
        counts: dict[str, int] = {}
        for fm in FIELD_RE.finditer(header):
            counts[fm.group(1)] = counts.get(fm.group(1), 0) + 1
        for fname, n in counts.items():
            if n > 1 and fname in TOP_LEVEL_FIELDS:
                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=Severity.BLOCK,
                    repo=None,
                    file=rel,
                    line=_line_of(text, abs_offset),
                    detail=(
                        f"realData entry for {nct} has field {fname!r} "
                        f"declared {n} times in its header; JS keeps the "
                        f"last value silently — earlier values are dead"
                    ),
                    fix_hint=(
                        f"remove the duplicate {fname!r} declaration; verify "
                        f"the surviving value matches the published trial"
                    ),
                    source=SOURCE,
                    timestamp=now,
                ))

    return verdicts


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []

    for path in _iter_html_files(ctx.repo_root):
        rel = path.relative_to(ctx.repo_root).as_posix()
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for v in _check_one_file(text, rel, now):
            # Attach repo lazily so the helper can stay file-only
            verdicts.append(Verdict(
                rule_id=v.rule_id,
                severity=v.severity,
                repo=str(ctx.repo_root),
                file=v.file,
                line=v.line,
                detail=v.detail,
                fix_hint=v.fix_hint,
                source=v.source,
                timestamp=v.timestamp,
            ))

    return verdicts


def _iter_html_files(root: Path) -> Iterator[Path]:
    # Restrict to *_REVIEW.html — keeps scan budget tight.
    for path in iter_repo_files(root, '*_REVIEW.html', HTML_EXCLUDE_DIRS, population=POPULATION):
        yield path
