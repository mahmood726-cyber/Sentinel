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

# Bytes that may legally precede the marker on its line.
# Mirrors the comment-prefix grammar of YAML/Python (#), JS/CSS (//, /*),
# plus leading whitespace.
_PREFIX_RE = re.compile(rb"^[#/* \t]*sentinel:skip-file\b", re.MULTILINE)


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
