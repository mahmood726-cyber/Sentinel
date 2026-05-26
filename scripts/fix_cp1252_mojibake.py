"""Repair cp1252 mojibake in tracked text files.

Inverse of the corruption process described in sentinel/rules/plugins/cp1252_mojibake.py:
opening a UTF-8 file in a cp1252-defaulting editor and re-saving doubles
the encoding so the original character `—` becomes the 3-char sequence
`â€"`. This script reads each affected file, replaces the canonical
mojibake sequences with the original UTF-8 characters, and writes back
as UTF-8.

The replacement table mirrors MOJIBAKE_PATTERNS in the rule plugin
(longest-first to avoid partial-match collisions). Run --dry-run first
to see what would change.

Usage:
    python scripts/fix_cp1252_mojibake.py --repo F:/some-repo --dry-run
    python scripts/fix_cp1252_mojibake.py --repo F:/some-repo --apply
"""
# sentinel:skip-file — this script literally contains the mojibake sequences it's repairing.
from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path

if sys.platform == "win32" and "pytest" not in sys.modules:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Mojibake repair via algorithmic round-trip:
#
# Original bug: a UTF-8 file is read as cp1252 then re-saved as UTF-8.
# So a Unicode codepoint U whose UTF-8 encoding is N bytes b1 b2 ... bN
# becomes N separate Unicode codepoints — each one is the cp1252 decoding
# of the corresponding byte. To invert: take each suspicious "mojibake
# run" of chars, re-encode them as cp1252 to recover the original bytes,
# then decode those bytes as UTF-8.
#
# We only repair runs that:
#   1. Start with `â` (U+00E2) — the cp1252 decoding of UTF-8 byte 0xE2,
#      which is the lead byte for all U+2000-U+2FFF (typographic punct,
#      arrows, box-drawing, etc. — the practically-affected range).
#   2. Round-trip cleanly: every char in the run encodes to a single
#      cp1252 byte, and the resulting byte sequence decodes as valid
#      UTF-8 in the U+2000-U+2FFF range.
#
# This is safer than a hard-coded substitution table — past first-pass
# attempt had wrong target codepoints (ASCII `"` U+0022 vs curly close
# `"` U+201D) and `replace` ed the partial prefix, doubling the
# corruption. Algorithmic invert can't make that mistake.


# UTF-8 lead bytes that appear in cp1252 mojibake. Each lead byte
# determines the sequence length (2 / 3 / 4 bytes) per UTF-8's encoding
# rules. cp1252 decodes each byte to a specific Unicode char:
#
#   byte 0xC2 → `Â` (U+00C2)  : 2-byte UTF-8 → U+0080-U+07FF range
#   byte 0xC3 → `Ã` (U+00C3)  : 2-byte UTF-8 → accented Latin (À-ÿ)
#   byte 0xE2 → `â` (U+00E2)  : 3-byte UTF-8 → U+2000-U+2FFF (punct/symbol)
#   byte 0xEF → `ï` (U+00EF)  : 3-byte UTF-8 → e.g. U+FE00-U+FFFF (VS / arrows)
#   byte 0xF0 → `ð` (U+00F0)  : 4-byte UTF-8 → emoji (U+1F000+)
#
# Acceptable target Unicode ranges, per lead byte:
LEAD_BYTE_TARGETS = {
    "Â": (0x0080, 0x07FF, 2),    # Latin-1 supplement + Latin Extended
    "Ã": (0x0080, 0x07FF, 2),
    "â": (0x2000, 0x2FFF, 3),    # General Punctuation through Supplemental Arrows
    "ï": (0x2E00, 0xFFFD, 3),    # CJK punctuation through Special Variations
    "ð": (0x10000, 0x1FFFF, 4),  # Supplementary Multilingual Plane (emoji etc.)
}


def _try_demojibake_run(text: str, start: int) -> tuple[str, int] | None:
    """If text[start:start+N] is an N-char cp1252-mojibake of an acceptable-
    range Unicode codepoint, return (original_char, N). Otherwise None.

    The acceptable range varies by lead byte — see LEAD_BYTE_TARGETS.
    Conservative ranges keep false positives near zero: legitimate French
    `âge` / `câble` have `â` followed by ASCII chars that can't encode
    back to UTF-8 continuation bytes, so the round-trip fails harmlessly.
    """
    if start >= len(text):
        return None
    target = LEAD_BYTE_TARGETS.get(text[start])
    if target is None:
        return None
    lo, hi, n_bytes = target
    if start + n_bytes > len(text):
        return None
    try:
        bs = bytearray()
        for j in range(n_bytes):
            ch = text[start + j]
            encoded = ch.encode("cp1252", errors="strict")
            if len(encoded) != 1:
                return None
            bs.append(encoded[0])
        original = bs.decode("utf-8", errors="strict")
        if len(original) != 1:
            return None
        if not (lo <= ord(original) <= hi):
            return None
        return (original, n_bytes)
    except (UnicodeEncodeError, UnicodeDecodeError, ValueError):
        return None


def _fix_text(text: str) -> tuple[str, int]:
    """Walk the text, replacing each algorithmic-recoverable mojibake run."""
    out: list[str] = []
    i = 0
    n = len(text)
    total = 0
    while i < n:
        if text[i] in LEAD_BYTE_TARGETS:
            recovered = _try_demojibake_run(text, i)
            if recovered is not None:
                ch, consumed = recovered
                out.append(ch)
                i += consumed
                total += 1
                continue
        out.append(text[i])
        i += 1
    return "".join(out), total


def _walk_repo(root: Path):
    """Yield Path objects for tracked text files. Uses git ls-files when
    available; falls back to rglob on text extensions."""
    import subprocess
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True, timeout=30, check=False,
        )
        if result.returncode == 0:
            for raw in result.stdout.split(b"\0"):
                if not raw:
                    continue
                p = root / raw.decode("utf-8", errors="replace")
                if p.is_file():
                    yield p
            return
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    # Fallback
    text_exts = {".py", ".md", ".html", ".htm", ".js", ".mjs", ".cjs",
                 ".ts", ".json", ".yaml", ".yml", ".txt", ".rst",
                 ".toml", ".ini", ".cfg", ".csv", ".r", ".R"}
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in text_exts:
            yield p


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="repo root to scan")
    ap.add_argument("--apply", action="store_true", help="write fixes; default is dry-run")
    args = ap.parse_args(argv)

    root = Path(args.repo).resolve()
    if not root.is_dir():
        sys.stderr.write(f"not a directory: {root}\n")
        return 1

    fixed_files = 0
    total_repls = 0
    for p in _walk_repo(root):
        try:
            text = p.read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, OSError):
            continue
        if "â" not in text:
            continue
        new_text, count = _fix_text(text)
        if count == 0 or new_text == text:
            continue
        rel = p.relative_to(root).as_posix()
        print(f"  {'WOULD FIX' if not args.apply else 'FIXED'}  {count:4d}  {rel}")
        if args.apply:
            p.write_text(new_text, encoding="utf-8")
        fixed_files += 1
        total_repls += count

    print(f"\n{'Would fix' if not args.apply else 'Fixed'}: {fixed_files} files, {total_repls} mojibake sequences")
    return 0


if __name__ == "__main__":
    sys.exit(main())
