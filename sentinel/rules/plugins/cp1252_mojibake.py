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

# Canonical mojibake sequences. Each one is "â" + a specific cp1252-byte-
# misread of a common UTF-8 punctuation/symbol codepoint. Anchored to
# avoid matching legitimate words like "âge" or "câble" in French text.
MOJIBAKE_PATTERNS = {
    "â”€": "─ (BOX DRAWINGS LIGHT HORIZONTAL)",
    "â”â": "│ (BOX DRAWINGS LIGHT VERTICAL — chained mojibake form)",
    "â€\"": "— (EM DASH)",       # the trailing " is part of the corruption
    "â€™": "' (RIGHT SINGLE QUOTATION)",
    "â€˜": "' (LEFT SINGLE QUOTATION)",
    "â€œ": '" (LEFT DOUBLE QUOTATION)',
    "â€": '" (RIGHT DOUBLE QUOTATION — partial)',
    "â€¦": "… (HORIZONTAL ELLIPSIS)",
    "â˜…": "★ (BLACK STAR)",
    "â–ˆ": "█ (FULL BLOCK)",
    "â–€": "▀ (UPPER HALF BLOCK)",
    "â–": "▄ (LOWER HALF BLOCK / general box-drawing)",
    "â—": "○/● (geometric circle family)",
    "â†’": "→ (RIGHTWARDS ARROW)",
    "â†": "← (LEFTWARDS ARROW)",
}

_PATTERN_RE = re.compile(
    "|".join(re.escape(k) for k in sorted(MOJIBAKE_PATTERNS, key=len, reverse=True))
)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


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
        # Cheap pre-filter: skip files without the `â` lead byte.
        if "â" not in text:
            continue
        rel = path.relative_to(root).as_posix()
        # Find all distinct mojibake offsets, report at most 1 per file
        # (one detection is enough — operator opens the file and fixes).
        m = _PATTERN_RE.search(text)
        if not m:
            continue
        # Identify which pattern actually matched for the diagnostic.
        seq = m.group(0)
        glyph_label = MOJIBAKE_PATTERNS.get(seq, "(unknown)")
        # Total count to surface the scope of corruption.
        total = len(_PATTERN_RE.findall(text))
        verdicts.append(Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=str(root),
            file=rel,
            line=_line_of(text, m.start()),
            detail=(
                f"cp1252-mojibake byte sequence `{seq}` ({glyph_label}) "
                f"at line {_line_of(text, m.start())}; {total} total "
                "match(es) in file — file was likely opened in a cp1252 "
                "editor and re-saved, corrupting all non-ASCII chars"
            ),
            fix_hint=(
                "if the corruption dominates the diff, `git checkout` "
                "the file and re-apply only the real change; otherwise "
                "open in a UTF-8 editor and fix the affected glyphs"
            ),
            source=SOURCE,
            timestamp=now,
        ))
    return verdicts
