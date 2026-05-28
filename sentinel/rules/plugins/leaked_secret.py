# sentinel:skip-file — this file contains secret-format patterns by necessity
"""P1-leaked-secret: WARN when a tracked file contains a string that
looks like a real credential (API key, token, private-key header).

Covers the credential classes most commonly committed by accident:

  - AWS access key IDs            AKIA/ASIA/AGPA/AIDA prefix + 16 chars
  - Anthropic API keys            sk-ant-(api|admin)\\d+-...
  - OpenAI API keys               sk-[48chars] or sk-proj-...
  - GitHub tokens                 ghp_ / gho_ / ghu_ / ghs_ / ghr_ / github_pat_
  - Slack tokens                  xoxb- / xoxp- / xoxa- / xoxr-
  - Stripe live keys              sk_live_ / rk_live_
  - Google API key                AIzaSy[A-Za-z0-9_-]{33}
  - Generic private-key headers   -----BEGIN ... PRIVATE KEY-----

Severity: WARN (not BLOCK).

Rationale for starting at WARN: a BLOCK-tier rule that fires on a
false positive (e.g. a test fixture that happens to match) hard-blocks
pushes, which is the exact failure mode Sentinel warns against for
P0-placeholder-hmac. We start at WARN, run a portfolio sweep, suppress
fixtures via `sentinel:skip-file`, then promote to BLOCK after zero
false positives across a week. See review-findings.md (2026-04-19).

False-positive protection:
  - Respects the `sentinel:skip-file` marker (handled by scanner).
  - Skips anything under tests/fixtures/, docs/, node_modules/.
  - Skips anything whose line contains the word `EXAMPLE`, `fake`,
    `dummy`, `test`, or `placeholder` within 40 chars of the match
    (these are overwhelmingly documentation, not real leaks).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import DEFAULT_EXCLUDE_DIRS, iter_repo_files
from sentinel.io.skip_marker import has_skip_marker


ID = "P1-leaked-secret"
# Promoted WARN -> BLOCK on 2026-04-19 after a portfolio sweep
# across 467 repos returned 0 real findings. See sweep output
# archived at C:/Sentinel/scripts/sweep_leaked_secret.py.
SEVERITY = Severity.BLOCK
SOURCE = "lessons.md#cryptography--signing-learned-2026-04-14"
SCOPE = "repo"

SCAN_EXCLUDE_DIRS = DEFAULT_EXCLUDE_DIRS | {
    "fixtures", "docs", "site-packages", ".venv", "venv",
}

# File extensions we scan. Binary formats explicitly skipped.
SCAN_EXTENSIONS = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".md", ".txt", ".sh", ".bat", ".ps1",
    ".env", ".envrc", "",  # .env without extension
}

# Max bytes to read per file. Huge files are rarely config.
MAX_FILE_BYTES = 2_000_000

# Words near a match that strongly indicate documentation / fixture.
SAFE_CONTEXT_WORDS = re.compile(
    r"(?i)\b(example|placeholder|dummy|fake|sample|mock|test[-_ ]?key|redacted|xxx+|your[-_ ]?)\b",
)

# (name, pattern) tuples. Patterns are word-boundary-anchored where
# the credential format allows, and otherwise tight enough to resist
# false positives. Order is irrelevant — we dedupe per-line.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key",
     re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b")),
    ("Anthropic API key",
     re.compile(r"\bsk-ant-(?:api|admin)\d+-[A-Za-z0-9_\-]{32,}\b")),
    ("OpenAI API key",
     # Legacy: sk-<48 alphanum, no dashes>. Project: sk-proj-<body>.
     # The no-dash body is what distinguishes OpenAI keys from other
     # sk-<provider>- prefixes (e.g. Anthropic's sk-ant-).
     re.compile(r"\bsk-(?:proj-[A-Za-z0-9_\-]{32,}|[A-Za-z0-9]{48})\b")),
    ("GitHub token",
     re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{80,})\b")),
    ("Slack token",
     re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b")),
    ("Stripe live key",
     re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b")),
    ("Google API key",
     re.compile(r"\bAIzaSy[A-Za-z0-9_\-]{33}\b")),
    ("Private key header",
     re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |PGP |DSA |ENCRYPTED )?PRIVATE KEY-----")),
)


def _is_scannable(path: Path) -> bool:
    if path.suffix.lower() in SCAN_EXTENSIONS:
        return True
    # allow extensionless config like `.env`
    if not path.suffix and path.name.startswith("."):
        return True
    return False


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    seen_locations: set[tuple[str, int, str]] = set()

    for path in iter_repo_files(ctx.repo_root, "*", SCAN_EXCLUDE_DIRS):
        if not _is_scannable(path):
            continue
        # Honor the file-level skip marker — secret-redaction tools and
        # secret-format documentation legitimately contain key patterns.
        # The module docstring claimed the scanner handled this, but the
        # repo-scan path never applied it (fixed 2026-05-28 after
        # e156-student-starter/tools/get_unstuck.py — a redaction utility —
        # tripped the rule on its own private-key-header regex).
        if has_skip_marker(path):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel = path.relative_to(ctx.repo_root).as_posix()
        lines = text.splitlines()

        for lineno, line in enumerate(lines, start=1):
            # Quick reject: if no prefix keyword appears, skip the
            # expensive regex pass. Cuts scan time ~10x on most files.
            if not any(
                token in line
                for token in (
                    "AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA",
                    "ANPA", "ANVA", "ASCA",
                    "sk-ant-", "sk-", "ghp_", "gho_", "ghu_", "ghs_",
                    "ghr_", "github_pat_",
                    "xox", "sk_live_", "rk_live_", "AIzaSy",
                    "BEGIN ",
                )
            ):
                continue

            for name, pat in _PATTERNS:
                m = pat.search(line)
                if not m:
                    continue
                # False-positive shield: skip if the line mentions an
                # example/placeholder/test context near the match.
                window_start = max(0, m.start() - 40)
                window_end = min(len(line), m.end() + 40)
                if SAFE_CONTEXT_WORDS.search(line[window_start:window_end]):
                    continue
                key = (rel, lineno, name)
                if key in seen_locations:
                    continue
                seen_locations.add(key)
                preview = m.group(0)
                if len(preview) > 12:
                    preview = preview[:6] + "..." + preview[-4:]
                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=SEVERITY,
                    repo=str(ctx.repo_root),
                    file=rel,
                    line=lineno,
                    detail=f"possible {name} in {rel}:{lineno} ({preview})",
                    fix_hint=(
                        f"if this is a real credential, rotate it NOW, "
                        f"`git rm --cached {rel}`, and re-scan history with "
                        "gitleaks/trufflehog. If it's a test/doc example, add "
                        "'sentinel:skip-file' marker at top of file or add "
                        "'example'/'placeholder' near the value."
                    ),
                    source=SOURCE,
                    timestamp=now,
                ))

    return verdicts
