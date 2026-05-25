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

# (mojibake bytes when read as UTF-8) → (original UTF-8 character)
# Longest-first matters: `â€"` (em-dash) must be tried before bare `â€`
# (right-double-quote partial) to avoid eating the leading 2 chars and
# leaving `"` orphaned.
FIXES = [
    ("â”€", "─"),     # box drawings light horizontal
    ("â€™", "'"),      # right single quote
    ("â€˜", "'"),      # left single quote
    ("â€œ", '"'),     # left double quote
    ("â€\"", "—"),    # em dash (3 chars: â + € + ")
    ("â€¦", "…"),     # horizontal ellipsis
    ("â€", '"'),       # right double quote (partial — match last since shortest)
    ("â˜…", "★"),     # black star
    ("â–ˆ", "█"),     # full block
    ("â–€", "▀"),     # upper half block
    ("â†'", "→"),     # rightwards arrow
    ("â†", "←"),       # leftwards arrow (partial)
]


def _fix_text(text: str) -> tuple[str, int]:
    """Apply all mojibake fixes. Returns (fixed_text, total_replacements)."""
    total = 0
    for bad, good in FIXES:
        if bad in text:
            count = text.count(bad)
            text = text.replace(bad, good)
            total += count
    return text, total


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
        if not any(bad in text for bad, _ in FIXES):
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
