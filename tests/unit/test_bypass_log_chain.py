"""Tests for the tamper-evident bypass-log hash chain (P1-5)."""
from __future__ import annotations

import hashlib

from sentinel.cli.bypass_log import verify_chain
from sentinel.hook.payload import make_hook_script


def _chain(entries: list[str]) -> list[str]:
    """Build a valid chained log from raw `ts\trepo\tuser` entries."""
    lines: list[str] = []
    prev = ""
    for entry in entries:
        h = hashlib.sha256((prev + entry).encode("utf-8")).hexdigest()
        lines.append(f"{entry}\t{h}")
        prev = h
    return lines


def test_valid_chain_passes():
    lines = _chain([
        "2026-06-21T00:00:00Z\trepoA\talice",
        "2026-06-21T01:00:00Z\trepoB\tbob",
    ])
    ok, bad, _ = verify_chain(lines)
    assert ok and bad is None


def test_tampered_middle_line_detected():
    lines = _chain([
        "2026-06-21T00:00:00Z\trepoA\talice",
        "2026-06-21T01:00:00Z\trepoB\tbob",
        "2026-06-21T02:00:00Z\trepoC\tcarol",
    ])
    # Tamper with the user field of the second entry, keep its recorded hash.
    parts = lines[1].split("\t")
    parts[2] = "mallory"
    lines[1] = "\t".join(parts)
    ok, bad, _ = verify_chain(lines)
    assert not ok
    assert bad == 2


def test_deleted_line_breaks_chain():
    lines = _chain([
        "2026-06-21T00:00:00Z\trepoA\talice",
        "2026-06-21T01:00:00Z\trepoB\tbob",
        "2026-06-21T02:00:00Z\trepoC\tcarol",
    ])
    del lines[1]  # drop the middle entry
    ok, bad, _ = verify_chain(lines)
    assert not ok


def test_legacy_unchained_lines_tolerated():
    lines = ["2026-06-01T00:00:00Z\trepoX\told"]  # 3 fields, pre-chain
    ok, bad, msg = verify_chain(lines)
    assert ok and bad is None
    assert "legacy" in msg


def test_hook_script_contains_chain_logic():
    script = make_hook_script("block")
    assert "sha256sum" in script
    assert "prev_chain" in script
    # No leftover f-string artifacts (doubled braces should have collapsed).
    assert "{{" not in script and "}}" not in script
    # awk field-print must survive intact.
    assert "{print $4}" in script
