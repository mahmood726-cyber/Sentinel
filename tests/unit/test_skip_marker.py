"""Tests for sentinel.io.skip_marker.has_skip_marker.

Per the 8-persona blinded review (P0-8 Red-Team + Test Coverage), the
prior substring-match implementation false-suppressed on `# not-sentinel:skip-file`
and on the marker appearing past the 1024-byte scan window. The new
anchored implementation must:

1. Honor canonical placements (line 1 / line 2, with comment-prefix)
2. Reject the marker when it appears as a substring of another word
3. Reject the marker when it appears past the scan-window
4. Survive UTF-8 BOM (3 bytes consumed without resetting the line-1 anchor)
5. Survive non-UTF-8 bytes (operate on raw bytes, not decoded text)
"""
from __future__ import annotations

from pathlib import Path

from sentinel.io.skip_marker import has_skip_marker, SKIP_MARKER_SCAN_BYTES


def _write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_marker_on_line1_python_comment(tmp_path):
    p = tmp_path / "f.py"
    _write(p, b"# sentinel:skip-file\nprint('ok')\n")
    assert has_skip_marker(p) is True


def test_marker_on_line1_js_double_slash(tmp_path):
    p = tmp_path / "f.js"
    _write(p, b"// sentinel:skip-file\nconsole.log('ok');\n")
    assert has_skip_marker(p) is True


def test_marker_on_line1_js_block_comment(tmp_path):
    p = tmp_path / "f.js"
    _write(p, b"/* sentinel:skip-file */\nconsole.log('ok');\n")
    assert has_skip_marker(p) is True


def test_marker_bare_no_comment_prefix(tmp_path):
    """Workbook usage: the marker is bare, not commented, on line 2."""
    p = tmp_path / "workbook.txt"
    _write(p, b"E156 REWRITE WORKBOOK\nsentinel:skip-file\n(notes...)\n")
    assert has_skip_marker(p) is True


def test_marker_after_shebang(tmp_path):
    p = tmp_path / "script.py"
    _write(p, b"#!/usr/bin/env python\n# sentinel:skip-file\nimport os\n")
    assert has_skip_marker(p) is True


def test_marker_substring_xsentinel_rejected(tmp_path):
    """The substring-match bug: `xsentinel:skip-file` must NOT suppress."""
    p = tmp_path / "f.py"
    _write(p, b"# xsentinel:skip-file\nbad code\n")
    assert has_skip_marker(p) is False


def test_marker_substring_negation_rejected(tmp_path):
    """`not-sentinel:skip-file` is a deliberate anti-marker, must NOT suppress."""
    p = tmp_path / "f.py"
    _write(p, b"# not-sentinel:skip-file\nbad code\n")
    assert has_skip_marker(p) is False


def test_marker_inline_in_string_rejected(tmp_path):
    """Marker inside a string literal mid-file (column != 0) must NOT suppress."""
    p = tmp_path / "f.py"
    _write(p, b'msg = "the canonical marker is sentinel:skip-file in headers"\nbad code\n')
    assert has_skip_marker(p) is False


def test_marker_beyond_scan_window_rejected(tmp_path):
    """Marker past byte SKIP_MARKER_SCAN_BYTES must NOT suppress."""
    p = tmp_path / "f.py"
    padding = b"# pad\n" * (SKIP_MARKER_SCAN_BYTES // 6 + 5)
    _write(p, padding + b"# sentinel:skip-file\nbad code\n")
    assert has_skip_marker(p) is False


def test_marker_with_utf8_bom(tmp_path):
    """UTF-8 BOM (3 bytes) must not consume the line-1 anchor."""
    p = tmp_path / "f.py"
    _write(p, b"\xef\xbb\xbf# sentinel:skip-file\nimport os\n")
    assert has_skip_marker(p) is True


def test_marker_with_non_utf8_bytes(tmp_path):
    """Non-UTF-8 bytes elsewhere in head should not break detection."""
    p = tmp_path / "f.py"
    _write(p, b"# sentinel:skip-file\n\xff\xfe\xfd binary garbage\n")
    assert has_skip_marker(p) is True


def test_no_marker_returns_false(tmp_path):
    p = tmp_path / "f.py"
    _write(p, b"import os\nprint('hello')\n")
    assert has_skip_marker(p) is False


def test_unreadable_path_returns_false(tmp_path):
    """Missing file → False (fail-closed: rule scans normally)."""
    p = tmp_path / "does_not_exist.py"
    assert has_skip_marker(p) is False


def test_empty_file_returns_false(tmp_path):
    p = tmp_path / "empty.py"
    _write(p, b"")
    assert has_skip_marker(p) is False
