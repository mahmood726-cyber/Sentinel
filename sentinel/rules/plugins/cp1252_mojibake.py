# sentinel:skip-file — docstring example characters ARE the mojibake patterns.
"""P1-cp1252-mojibake: WARN on UTF-8 files containing canonical
cp1252-misread byte sequences.

Past incident (lessons.md "cp1252 save corruption — detect via
mojibake", 2026-04-16, EvidenceOracle): a UTF-8 source file is opened
in a cp1252-defaulting editor (some Windows tools, some Sublime
configurations, some web-form pastes) and re-saved. Each non-ASCII
UTF-8 codepoint gets misinterpreted as one cp1252 byte per UTF-8
byte, then re-encoded:

    `─` (U+2500 BOX DRAWINGS LIGHT HORIZONTAL) → `â”€`
    `—` (U+2014 EM DASH)                       → `â€"`
    `★` (U+2605 BLACK STAR)                    → `â˜…`
    `'` (U+2019 RIGHT SINGLE QUOTATION MARK)   → `â€™`
    `…` (U+2026 HORIZONTAL ELLIPSIS)           → `â€¦`

The damage is silent: file reads fine; git diff shows huge encoding
noise around the actual change; reverting+re-applying the real edit
becomes faster than untangling the corruption.

The rule scans every tracked text file (.py, .md, .html, .js, .json,
.yaml, .yml, .txt) for the canonical mojibake sequences. Anchored on
the `â` prefix, which is the cp1252 representation of the UTF-8
continuation byte for any of these glyphs. False-positive risk is
low because `â` followed by these specific punctuation/symbol bytes
is rare in legitimate French/Portuguese/Vietnamese text.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import iter_repo_files
from sentinel.io.skip_marker import has_skip_marker


ID = "P1-cp1252-mojibake"
SEVERITY = Severity.WARN
SOURCE = "lessons.md#portfolio-audit-patterns-learned-2026-04-16  (cp1252 save corruption — detect via mojibake)"
SCOPE = "repo"

MAX_FILE_BYTES = 5_000_000
TEXT_EXCLUDE_DIRS = (".venv", "venv", "__pycache__", "build", "dist",
                     ".tox", ".pytest_cache", "node_modules", ".git",
                     "site-packages")
TEXT_EXTENSIONS = ("*.py", "*.md", "*.html", "*.htm", "*.js", "*.mjs",
                   "*.cjs", "*.ts", "*.json", "*.yaml", "*.yml", "*.txt",
                   "*.rst", "*.toml", "*.ini", "*.cfg", "*.csv", "*.r",
                   "*.R")

# Detection via algorithmic round-trip: for each `â` (U+00E2, cp1252 read of
# UTF-8 lead byte 0xE2), try interpreting the next 2 chars as cp1252 bytes,
# reconstruct the original UTF-8 byte sequence E2 b2 b3, decode as UTF-8.
# If the decoded char falls in the U+2000–U+27FF range (General Punctuation,
# Arrows, Box Drawings, etc.), we've found a real mojibake — return the
# original char in the diagnostic so the operator sees what to recover.
#
# V1 used a hard-coded MOJIBAKE_PATTERNS table with codepoint mismatches
# (e.g. ASCII `"` U+0022 where the actual mojibake 3rd-char is curly `"`
# U+201D). V1 still fired because the bare `â€` 2-char prefix matched all
# longer variants as a fallback, but the diagnostic LABELS were wrong.
# Algorithmic detection can't make codepoint-mismatch mistakes by
# construction, matches the fix script's logic, and gives accurate
# per-glyph diagnostics.


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _try_decode_mojibake_run(text: str, start: int) -> tuple[str, int] | None:
    """If text[start:start+3] is a 3-char cp1252 mojibake of a U+2000–U+27FF
    codepoint, return (original_char, consumed=3). Else None."""
    if start + 3 > len(text) or text[start] != "â":
        return None
    try:
        bs = bytearray()
        for j in range(3):
            ch = text[start + j]
            encoded = ch.encode("cp1252", errors="strict")
            if len(encoded) != 1:
                return None
            bs.append(encoded[0])
        if bs[0] != 0xE2:
            return None
        original = bs.decode("utf-8", errors="strict")
        if len(original) != 1:
            return None
        if not (0x2000 <= ord(original) <= 0x27FF):
            return None
        return (original, 3)
    except (UnicodeEncodeError, UnicodeDecodeError, ValueError):
        return None


def _find_mojibake(text: str) -> tuple[int, str, int] | None:
    """Walk the text; return (offset, recovered_original_char, total_count)
    for the first mojibake run found. None if no mojibake."""
    first: tuple[int, str] | None = None
    total = 0
    i = 0
    n = len(text)
    while i < n:
        if text[i] == "â":
            run = _try_decode_mojibake_run(text, i)
            if run is not None:
                ch, consumed = run
                if first is None:
                    first = (i, ch)
                total += 1
                i += consumed
                continue
        i += 1
    if first is None:
        return None
    return first[0], first[1], total


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    root = ctx.repo_root
    for path in iter_repo_files(root, TEXT_EXTENSIONS, TEXT_EXCLUDE_DIRS):
        if has_skip_marker(path):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Cheap pre-filter: skip files without the `â` (U+00E2) lead byte.
        if "â" not in text:
            continue
        result = _find_mojibake(text)
        if result is None:
            continue
        offset, original_char, total = result
        rel = path.relative_to(root).as_posix()
        # Pretty-print the recovered char + its Unicode name for the
        # diagnostic. Skip if name lookup fails (rare on the U+2000-U+27FF range).
        try:
            import unicodedata
            name = unicodedata.name(original_char)
        except (TypeError, ValueError):
            name = f"U+{ord(original_char):04X}"
        verdicts.append(Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=str(root),
            file=rel,
            line=_line_of(text, offset),
            detail=(
                f"cp1252-mojibake of `{original_char}` ({name}) at "
                f"line {_line_of(text, offset)}; {total} total recoverable "
                "sequence(s) in file — file was likely opened in a "
                "cp1252-defaulting editor and re-saved"
            ),
            fix_hint=(
                "run `python F:/Sentinel/scripts/fix_cp1252_mojibake.py "
                "--repo <root> --apply` to repair in place, OR if the "
                "corruption dominates a diff `git checkout` the file and "
                "re-apply only the real change"
            ),
            source=SOURCE,
            timestamp=now,
        ))
    return verdicts
