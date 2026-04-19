"""P2-html-a11y-basics: INFO on basic WCAG failures in tracked HTML.

Checks four of the most common, most-easily-fixable a11y gaps. These
are static regex checks — not a substitute for axe-core or a real
screen-reader test, but enough to surface the obvious misses that
shipped across the portfolio for years.

What this catches (and why these four):

  1. `<html>` without `lang=` — screen readers default to user locale,
     which is often wrong for scientific content. One-line fix.
  2. Missing `<title>` — browser tab / assistive-tech page label.
     One-line fix.
  3. `<img>` without `alt=` — blind users get no description. The
     single most impactful a11y gap in shipped HTML.
  4. `<input>` / `<select>` / `<textarea>` without either `aria-label=`
     or a `<label for="id">` pointing at it — keyboard users can't
     tell what the control is for. Checks the same file for
     `for="<id>"` matching the control's id.

Intentionally NOT checked here (out of scope for regex — needs DOM):
  - Color contrast (needs computed style / axe-core).
  - Tab order / focus-visible.
  - aria-live on dynamically-updating regions.
  - Heading hierarchy (h1 -> h2 -> h3).

Severity: INFO (never blocks, never warns — pure visibility). This
rule is meant to be aggregated nightly by Overmind and shown on a
dashboard, not to gate pushes. Per the skill-scoped review of the
/spec-html template (2026-04-19), accessibility is required for new
apps; this rule catches the existing portfolio's backlog.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List, Set

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import HTML_EXCLUDE_DIRS, iter_repo_files


ID = "P2-html-a11y-basics"
SEVERITY = Severity.INFO
SOURCE = "lessons.md#html-apps"
SCOPE = "repo"

MAX_FILE_BYTES = 5_000_000  # skip giants; same as dashboard_stat_orphan

# <html ...> opening tag, with or without attrs.
_HTML_OPEN = re.compile(r"<html\b([^>]*)>", re.IGNORECASE)

# Presence of a <title>...</title> element (anywhere).
_TITLE = re.compile(r"<title\b[^>]*>[^<]*</title>", re.IGNORECASE)

# <img ...> opening tag — capture attrs for alt detection.
_IMG = re.compile(r"<img\b([^>]*)>", re.IGNORECASE)

# <input|select|textarea ...> opening tag — capture attrs.
_CONTROL = re.compile(
    r"<(input|select|textarea)\b([^>]*)>", re.IGNORECASE,
)

# id="<value>" inside a tag's attr blob.
_ATTR_ID = re.compile(r"""\bid\s*=\s*["']([^"']+)["']""", re.IGNORECASE)

# aria-label / aria-labelledby / title (as label surrogate) / alt on attr blob.
_ATTR_ARIA_LABEL = re.compile(
    r"""\b(?:aria-label|aria-labelledby|title)\s*=\s*["']""",
    re.IGNORECASE,
)

_ATTR_ALT = re.compile(r"""\balt\s*=\s*["']""", re.IGNORECASE)

# <label for="<id>"> in a file — tells us which control ids have labels.
_LABEL_FOR = re.compile(
    r"""<label\b[^>]*\bfor\s*=\s*["']([^"']+)["']""", re.IGNORECASE,
)

# Controls with type="hidden" | "submit" | "button" | "reset" don't need
# a user-visible label. Same for <input type="image"> (needs alt instead).
_TYPE_ATTR = re.compile(r"""\btype\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_NO_LABEL_REQUIRED_TYPES = {"hidden", "submit", "button", "reset"}


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []

    for path in _iter_html_files(ctx.repo_root):
        rel = path.relative_to(ctx.repo_root).as_posix()
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        verdicts.extend(_check_file(ctx, rel, text, now))

    return verdicts


def _check_file(
    ctx: RepoContext, rel: str, text: str, now: "datetime",
) -> List[Verdict]:
    out: List[Verdict] = []
    repo = str(ctx.repo_root)

    # (1) <html> without lang=
    m_html = _HTML_OPEN.search(text)
    if m_html is not None:
        attrs = m_html.group(1)
        if "lang=" not in attrs.lower():
            out.append(Verdict(
                rule_id=ID, severity=SEVERITY, repo=repo, file=rel,
                line=text.count("\n", 0, m_html.start()) + 1,
                detail=f"<html> without lang= attribute in {rel}",
                fix_hint='add lang="en" (or the correct BCP-47 code) to <html>',
                source=SOURCE, timestamp=now,
            ))

    # (2) missing <title>
    if _HTML_OPEN.search(text) and not _TITLE.search(text):
        out.append(Verdict(
            rule_id=ID, severity=SEVERITY, repo=repo, file=rel,
            line=None,
            detail=f"no <title> element found in {rel}",
            fix_hint="add <title>Your App Name</title> inside <head>",
            source=SOURCE, timestamp=now,
        ))

    # (3) <img> without alt=
    for m_img in _IMG.finditer(text):
        attrs = m_img.group(1)
        if _ATTR_ALT.search(attrs) is None:
            out.append(Verdict(
                rule_id=ID, severity=SEVERITY, repo=repo, file=rel,
                line=text.count("\n", 0, m_img.start()) + 1,
                detail=f"<img> without alt= in {rel}",
                fix_hint=(
                    'add alt="<description>" for content images, '
                    'or alt="" for purely decorative images'
                ),
                source=SOURCE, timestamp=now,
            ))

    # (4) form controls without a visible label
    labeled_ids: Set[str] = set(_LABEL_FOR.findall(text))
    for m_ctrl in _CONTROL.finditer(text):
        attrs = m_ctrl.group(2)
        type_m = _TYPE_ATTR.search(attrs)
        if type_m and type_m.group(1).lower() in _NO_LABEL_REQUIRED_TYPES:
            continue
        if _ATTR_ARIA_LABEL.search(attrs):
            continue  # self-labeled via aria-label / aria-labelledby
        id_m = _ATTR_ID.search(attrs)
        if id_m and id_m.group(1) in labeled_ids:
            continue  # paired with a <label for="id">
        tag = m_ctrl.group(1).lower()
        lineno = text.count("\n", 0, m_ctrl.start()) + 1
        out.append(Verdict(
            rule_id=ID, severity=SEVERITY, repo=repo, file=rel,
            line=lineno,
            detail=(
                f"<{tag}> without associated <label for=...> or aria-label "
                f"in {rel}:{lineno}"
            ),
            fix_hint=(
                f'add <label for="<id>">Description</label> and set the '
                f"same id on the <{tag}>; or add aria-label=\"Description\" "
                f"directly on the <{tag}>"
            ),
            source=SOURCE, timestamp=now,
        ))

    return out


def _iter_html_files(root: Path) -> Iterator[Path]:
    return iter_repo_files(root, "*.html", HTML_EXCLUDE_DIRS)
