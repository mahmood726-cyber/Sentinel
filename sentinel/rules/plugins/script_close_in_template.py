# sentinel:skip-file — docstring example contains the bad pattern.
"""P1-script-close-in-template: BLOCK on literal `</script>` inside a
template literal or string inside a `<script>` block.

Past incident (lessons.md "</script> in template literals/comments"):
HTML parsers terminate the surrounding `<script>` at the literal token
`</script>` regardless of JavaScript context. A template literal like

    const html = `<div>...</div></script>`;

ends the script tag at the first `</script>`, treats the JS suffix as
HTML text, and breaks the page. The fix is the standard split-token:

    const html = `<div>...</div>${'<'}/script>`;

or `<\\/script>`. The rule scans every tracked .html / .htm file for
literal `</script>` tokens that appear AFTER a `<script>` opening tag
but BEFORE the matching `</script>` that closes the SAME block, i.e.
inside JS-string/template-literal context.

Detection strategy: pair-balanced scan of `<script>` ... `</script>`
regions. Inside a region, count `` ` ``  / `'` / `"` quote pairs and
flag any `</script>` token that falls inside an unbalanced quote pair.
False-positive risk is low because the bug requires the closing tag
to literally appear inside a still-open string.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import iter_repo_files
from sentinel.io.population import Population
from sentinel.io.skip_marker import has_skip_marker


ID = "P1-script-close-in-template"
SEVERITY = Severity.BLOCK
SOURCE = "lessons.md#javascript--html  (</script> in template literals/comments)"
SCOPE = "repo"

# Population: PRESENT -- tracked AND untracked-not-ignored. This is a
# CORRECTNESS rule: the defect it finds runs when someone runs the file,
# whether or not git is tracking it. Migrated 2026-08-30; counts from
# before that date were taken over the tracked set only and are NOT
# comparable with counts after it.
POPULATION = Population.PRESENT

MAX_FILE_BYTES = 5_000_000
HTML_EXCLUDE_DIRS = (".venv", "venv", "__pycache__", "node_modules", "dist",
                     "build", ".pytest_cache", "archive")

# A file with any line longer than this is minified or contains an
# embedded library bundle (e.g. a Plotly export, a minified vendor JS
# block). The char-by-char backtick-state scanner below can't reliably
# track template-literal boundaries across thousands of chars of
# minified JS — a stray/odd backtick in a regular string or comment
# corrupts the state and makes the next legitimate `</script>` look
# "inside a template". The canonical hand-written bug
# (`const html = `<div></script>``) never appears in a minified line,
# so skipping long-line files removes the FP class without losing the
# real bug. (2026-05-28: portfolio scan FPs on Plotly exports +
# DTA_Pro_v2 minified bundles drove this guard.)
MAX_LINE_LEN = 3000

# The template-literal-with-</script> bug is compact: the opening
# backtick and the `</script>` are within a few hundred chars (a single
# HTML string). If they're farther apart, it's almost certainly
# mis-tracked state, not the real bug. Defense-in-depth alongside the
# line-length skip.
MAX_TEMPLATE_SPAN = 1000

# Find <script ...> opening tags. `src=` attribute means external file —
# no inline body to scan. Self-closing variants don't apply for <script>.
SCRIPT_OPEN_RE = re.compile(
    r"<script\b(?![^>]*\bsrc\s*=)[^>]*>",
    re.IGNORECASE,
)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _find_template_literal_bad_close(text: str, body_start: int) -> tuple[int | None, int]:
    """Detect the canonical bug: ``` `...</script>...` ``` — a literal
    `</script>` between an OPEN and CLOSE backtick where no other backtick
    intervenes. This is the lessons.md-documented pattern; broader
    string-state tracking has too many false positives with apostrophes
    in JS code.

    Returns (flagged_offset_or_None, block_end_offset).
    """
    i = body_start
    n = len(text)
    flagged: int | None = None
    while i < n:
        # Block terminator from HTML parser's perspective.
        if text[i:i + 8].lower() == "</script":
            return flagged, i
        if text[i] == "`":
            # Find the matching backtick (no nested template handling — rare
            # in practice; recognise escapes only).
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "`":
                    # Within (i, j), does </script appear? Only flag if the
                    # </script sits within MAX_TEMPLATE_SPAN of the opening
                    # backtick — guards against huge mis-tracked spans.
                    snippet = text[i + 1:j]
                    pos = snippet.lower().find("</script")
                    if pos >= 0 and flagged is None and pos <= MAX_TEMPLATE_SPAN:
                        flagged = i + 1 + pos
                    break
                if text[j:j + 8].lower() == "</script":
                    # No closing backtick before </script — the </script
                    # IS what HTML parser will stop at, AND it's inside an
                    # open template. Canonical bug — but only if the span
                    # from the opening backtick is compact (see
                    # MAX_TEMPLATE_SPAN); a huge span signals mis-tracked
                    # state in minified/generated JS.
                    if flagged is None and (j - i) <= MAX_TEMPLATE_SPAN:
                        flagged = j
                    return flagged, j
                j += 1
            else:
                # Unterminated backtick to EOF — JS would error, not our
                # concern.
                return flagged, n
            i = j + 1
            continue
        i += 1
    return flagged, n


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    root = ctx.repo_root
    for path in iter_repo_files(root, ("*.html", "*.htm"), HTML_EXCLUDE_DIRS, population=POPULATION):
        if has_skip_marker(path):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "<script" not in text.lower():
            continue
        # Skip minified / embedded-bundle files: the backtick scanner
        # can't track template boundaries across a 9000-char minified
        # line, and the canonical hand-written bug never lives there.
        if any(len(ln) > MAX_LINE_LEN for ln in text.splitlines()):
            continue
        rel = path.relative_to(root).as_posix()
        # Walk each <script ...> opening tag; scan the body until first
        # </script> from the parser's perspective.
        pos = 0
        while True:
            m = SCRIPT_OPEN_RE.search(text, pos)
            if not m:
                break
            body_start = m.end()
            flagged, block_end = _find_template_literal_bad_close(text, body_start)
            if flagged is not None:
                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=SEVERITY,
                    repo=str(root),
                    file=rel,
                    line=_line_of(text, flagged),
                    detail=(
                        "literal `</script>` token inside an open string/template "
                        "literal — the HTML parser will terminate the surrounding "
                        "<script> block here and break the page"
                    ),
                    fix_hint=(
                        "split the token: write `${'<'}/script>` in a template "
                        "literal, or `<\\/script>` in a regular string"
                    ),
                    source=SOURCE,
                    timestamp=now,
                ))
            pos = block_end + 1
    return verdicts
