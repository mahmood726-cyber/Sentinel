"""Per-file `sentinel:skip-file` marker detection.

Centralised so multiple rules don't drift on scan-window size, anchoring,
or BOM handling. Until 2026-05-06, this logic was duplicated byte-identical
in `js_parse_check.py` and `py_parse_check.py`. The 8-persona blinded review
flagged the duplication as a real DRY violation (any future fix to one
silently diverges) plus a substring-match false-suppression bug
(`# not-sentinel:skip-file` would silently suppress a real bug).

Anchoring rules:
- Marker MUST appear at column 0 of line 1 OR line 2 (line 1 may be a
  shebang). This prevents a malicious file with `// not-sentinel:skip-file`
  buried in mid-file from silently exempting itself.
- The marker must be preceded only by comment-prefix bytes
  (`#`, `//`, `/*`, ` `, `\t`) on its line — the canonical workbook usage
  (`sentinel:skip-file` as the second line of the E156 workbook) is bare,
  not commented, but anchored.
- Comparison done on bytes, not decoded text, so a mojibake'd marker
  cannot accidentally match after `errors="replace"` decoding.

Audit:
- Callers are encouraged to log marker honour to enable portfolio-wide
  reconciliation. The helper itself does not log (callers know the
  rule_id and file context).
"""
from __future__ import annotations

import re
from pathlib import Path

SKIP_FILE_MARKER = "sentinel:skip-file"
SKIP_MARKER_SCAN_BYTES = 1024

# Bytes that may legally precede the marker on its line. Three families:
#   1. Inline-style: `#`, `//`, `/*` plus leading whitespace —
#      matches Python/YAML, JS/C/CSS, etc. (the original grammar).
#   2. `REM` keyword (case-insensitive) — Windows .bat / .cmd. Requires
#      whitespace after the keyword so `REMsentinel:skip-file` (a
#      different identifier) does not match.
#   3. `::` colon-comment — also Windows .bat / .cmd; whitespace after is
#      optional because `::sentinel:skip-file` is a valid lead-in.
# Past incident (2026-05-06 nightly): C:/overmind/scripts/nightly_verify.bat
# line 2 (`REM sentinel:skip-file ...`) was being ignored because only
# family (1) was recognised, producing 13 false-positive hits on the .bat
# despite the marker being present.
# Added 2026-05-25: HTML comment prefix `<!--` to support .html test
# fixtures that legitimately contain intentional bug examples (the
# script-close-in-template rule's BAD fixture being the trigger).
_PREFIX_RE = re.compile(
    rb"^(?:[ \t]*(?i:rem)[ \t]+|[ \t]*::[ \t]*|[ \t]*<!--[ \t-]*|[#/* \t]*)sentinel:skip-file\b",
    re.MULTILINE,
)


def has_skip_marker(file_path: Path) -> bool:
    """Return True if the file's head carries an anchored skip-file marker.

    Reads up to SKIP_MARKER_SCAN_BYTES (1024) bytes. Returns False on any
    read error (caller's rule then proceeds normally — fail-closed for
    suppression, fail-open for normal scanning).

    Anchoring: the marker must appear at the start of one of the first
    few lines (after optional comment-prefix bytes), not as a substring
    in the middle of a string or comment elsewhere in the file. This
    prevents the false-suppression scenario where `# not-sentinel:skip-file`
    or `xsentinel:skip-file` would silently exempt a file from scanning.
    """
    try:
        head = file_path.read_bytes()[:SKIP_MARKER_SCAN_BYTES]
    except OSError:
        return False
    # Strip a UTF-8 BOM if present so it doesn't consume the line-1 anchor.
    if head.startswith(b"\xef\xbb\xbf"):
        head = head[3:]
    return _PREFIX_RE.search(head) is not None


# Per-line `# sentinel:skip-line` marker for narrow false-positive cases
# where the upstream guard isn't visible to the pattern matcher. Promoted
# from sentinel.registry.yaml_loader so plugin rules can honor the same
# convention without duplicating the parser. Syntax:
#
#   risky_call(x)  # sentinel:skip-line P0-foo-rule
#   risky_call(y)  # sentinel:skip-line P0-foo-rule, P1-bar-rule
#   risky_call(z)  # sentinel:skip-line   <- bare; suppresses all rules on line
#
# Or on the line immediately ABOVE:
#
#   # sentinel:skip-line P0-foo-rule
#   risky_call(w)
SKIP_LINE_MARKER = "sentinel:skip-line"


def line_is_suppressed(current_line: str, prev_line: str, rule_id: str) -> bool:
    """True if a `sentinel:skip-line` marker on `current_line` or
    `prev_line` suppresses `rule_id`. Both args are bare line strings
    (no trailing newline).

    Bare marker (no rule IDs after) suppresses all rules. Scoped form
    accepts space- or comma-separated rule IDs.
    """
    for candidate in (current_line, prev_line):
        idx = candidate.find(SKIP_LINE_MARKER)
        if idx == -1:
            continue
        after = candidate[idx + len(SKIP_LINE_MARKER):]
        tokens = [tok for tok in after.replace(",", " ").split() if tok]
        if not tokens:
            return True
        if rule_id in tokens:
            return True
    return False
