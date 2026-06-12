"""P0-denominator-logic: BLOCK on events > totals and on CIs that don't
bracket their point estimate.

E156 Assurance Standard "Data extraction errors" risk class. Per the
standard: "missing values; impossible numbers; mismatched denominators;
event counts greater than sample size; ... impossible confidence intervals".

This rule does the static, deterministic subset of those checks against
the inline `realData` blocks in rapidmeta-style review pages and against
the workbook + students.html.

BLOCK cases (impossible-by-arithmetic):
  - tE > tN  (treatment events exceed treatment total)
  - cE > cN  (control events exceed control total)
  - publishedHR with both bounds present, but NOT (hrLCI <= publishedHR <= hrUCI)

WARN cases (suspicious but not strictly impossible):
  - tN < 10 or cN < 10 on a trial labeled as phase 3 — single-digit cohort
    on a registration trial is usually a unit error
  - hrLCI == hrUCI (zero-width CI, almost always a data-entry error)

Scope: repo (commit-time). Targets `*_REVIEW.html` (rapidmeta dashboards)
and any other HTML/text file that contains a `realData` JS block.

Complementary to `rapidmeta_data_integrity` (which catches duplicate-key
shadowing and acronym collisions in the same blocks); this rule looks at
the arithmetic instead.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import path_allowed


ID = "P0-denominator-logic"
SEVERITY = Severity.BLOCK
SOURCE = "F:\\e156\\docs\\assurance-standard.md#2-data-checking"
SCOPE = "repo"

MAX_FILE_BYTES = 10_000_000

REALDATA_RE = re.compile(r"\brealData\b\s*[:=]\s*\{")
NCT_KEY_RE = re.compile(r"'(NCT\d{8})'\s*:\s*\{")
# Field captures inside a trial entry. Number can be int, float, or null/None.
# We accept both 'null' (the correct JS literal post-fix) and 'None' (pre-fix
# leftovers — rapidmeta_data_integrity will block the latter separately).
NUM_FIELD_RE = re.compile(
    r"\b(tE|tN|cE|cN|publishedHR|hrLCI|hrUCI|phase)\s*:\s*"
    r"(null|None|'[^']*'|-?\d+\.?\d*)",
)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _find_block_end(text: str, start_brace: int) -> int:
    depth = 0
    started = False
    limit = min(len(text), start_brace + 1_000_000)
    for j in range(start_brace, limit):
        c = text[j]
        if c == "{":
            depth += 1
            started = True
        elif c == "}":
            depth -= 1
            if started and depth == 0:
                return j
    return -1


def _parse_value(raw: str):
    """Parse a captured field value: null|None -> None; quoted str -> str; number -> float."""
    raw = raw.strip()
    if raw in ("null", "None"):
        return None
    if raw.startswith("'") and raw.endswith("'"):
        return raw[1:-1]
    try:
        f = float(raw)
        return int(f) if f.is_integer() else f
    except ValueError:
        return None


def _iter_realdata_entries(text: str):
    """Yield (nct, entry_text, abs_offset) for each NCT entry in realData."""
    m = REALDATA_RE.search(text)
    if not m:
        return
    block_start = m.end() - 1
    block_end = _find_block_end(text, block_start)
    if block_end < 0:
        return
    block = text[block_start:block_end + 1]
    for km in NCT_KEY_RE.finditer(block):
        nct = km.group(1)
        entry_open = block.find("{", km.end() - 1)
        entry_end = _find_block_end(block, entry_open)
        if entry_end < 0:
            continue
        entry = block[entry_open:entry_end + 1]
        yield nct, entry, block_start + entry_open


def _check_one_file(text: str, rel: str, now: datetime) -> List[Verdict]:
    verdicts: List[Verdict] = []
    if not REALDATA_RE.search(text):
        return verdicts

    for nct, entry, abs_offset in _iter_realdata_entries(text):
        fields = {}
        for fm in NUM_FIELD_RE.finditer(entry):
            k = fm.group(1)
            v = _parse_value(fm.group(2))
            # If a field appears multiple times within an entry header, the
            # LAST value wins in JS object literals (rapidmeta_data_integrity
            # catches that as a separate issue). We mirror that semantics.
            fields[k] = v

        line = _line_of(text, abs_offset)

        # BLOCK: events > totals
        for ev_key, n_key in (("tE", "tN"), ("cE", "cN")):
            ev = fields.get(ev_key)
            n = fields.get(n_key)
            if isinstance(ev, (int, float)) and isinstance(n, (int, float)):
                if ev > n:
                    verdicts.append(Verdict(
                        rule_id=ID,
                        severity=Severity.BLOCK,
                        repo=None,
                        file=rel,
                        line=line,
                        detail=(
                            f"trial {nct}: {ev_key}={ev} > {n_key}={n} "
                            f"(event count exceeds sample size — arithmetically impossible)"
                        ),
                        fix_hint=(
                            f"verify {ev_key} and {n_key} against the source paper. "
                            f"Common causes: percent vs count confusion, swapped fields, "
                            f"wrong-arm assignment"
                        ),
                        source=SOURCE,
                        timestamp=now,
                    ))

        # BLOCK: CI does not bracket point estimate
        hr = fields.get("publishedHR")
        lci = fields.get("hrLCI")
        uci = fields.get("hrUCI")
        if (isinstance(hr, (int, float)) and isinstance(lci, (int, float))
                and isinstance(uci, (int, float))):
            if not (lci <= hr <= uci):
                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=Severity.BLOCK,
                    repo=None,
                    file=rel,
                    line=line,
                    detail=(
                        f"trial {nct}: publishedHR={hr} not bracketed by CI "
                        f"({lci}, {uci}) — point estimate must lie inside its own CI"
                    ),
                    fix_hint=(
                        "re-extract from the source paper; common causes: "
                        "log/linear scale confusion, transposed bounds, "
                        "wrong-trial copy-paste"
                    ),
                    source=SOURCE,
                    timestamp=now,
                ))
            elif lci == uci:
                # WARN: zero-width CI almost always indicates a data-entry error
                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=Severity.WARN,
                    repo=None,
                    file=rel,
                    line=line,
                    detail=(
                        f"trial {nct}: hrLCI ({lci}) == hrUCI ({uci}) — "
                        f"zero-width CI is almost certainly a data-entry error"
                    ),
                    fix_hint="verify upper and lower bounds against the source paper",
                    source=SOURCE,
                    timestamp=now,
                ))

        # WARN: tiny cohort on phase-3 trial
        phase = fields.get("phase")
        for n_key in ("tN", "cN"):
            n = fields.get(n_key)
            if isinstance(n, (int, float)) and 0 < n < 10:
                if isinstance(phase, str) and phase.upper() in ("III", "3", "PHASE 3"):
                    verdicts.append(Verdict(
                        rule_id=ID,
                        severity=Severity.WARN,
                        repo=None,
                        file=rel,
                        line=line,
                        detail=(
                            f"trial {nct}: {n_key}={n} on a phase-3 trial — "
                            f"single-digit cohort is typically a unit error "
                            f"(thousands written as ones)"
                        ),
                        fix_hint="re-extract; check unit (n vs n×1000)",
                        source=SOURCE,
                        timestamp=now,
                    ))

    return verdicts


def _iter_html_files(root: Path):
    """Scan files likely to contain a realData block."""
    # rapidmeta dashboards are *_REVIEW.html at root
    for p in root.glob("*_REVIEW.html"):
        if not path_allowed(root, p):
            continue  # honor `scan --diff` changed-file scope
        yield p
    # Also students.html if present
    sp = root / "students.html"
    if sp.is_file():
        yield sp


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    root = ctx.repo_root
    for path in _iter_html_files(root):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(root).as_posix()
        for v in _check_one_file(text, rel, now):
            verdicts.append(Verdict(
                rule_id=v.rule_id,
                severity=v.severity,
                repo=str(root),
                file=v.file,
                line=v.line,
                detail=v.detail,
                fix_hint=v.fix_hint,
                source=v.source,
                timestamp=v.timestamp,
            ))
    return verdicts
