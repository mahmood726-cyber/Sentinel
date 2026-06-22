# sentinel:skip-file — docstring + patterns contain example CDN URLs.
"""P2-csp-external-resource: WARN when an HTML file declares a Content-Security-
Policy but loads a resource (script/img/iframe `src`, or a `<link>` stylesheet/
preconnect/icon `href`) from an external host that its OWN CSP does not permit.

This is a self-contradiction that is *both* an offline-contract violation and a
runtime bug: the page asserts a restrictive policy (e.g. `script-src 'self'
'unsafe-inline'; connect-src 'self'`) yet references e.g.
`<script src="https://cdn.plot.ly/...">` — which the browser will BLOCK at load,
silently breaking the feature. (Source: rules.md "HTML apps — Fully offline, no
external CDN"; the allmeta offline-hardening pass, 2026-06, found 16 such files.)

Why scoped to CSP-vs-host rather than "any external src": a portfolio has both
offline-first apps and legitimately-online pages. Flagging every CDN reference
would be noise. Restricting to "the page's OWN CSP forbids this host" yields a
near-zero-FP signal — the resource is provably broken on that page. Pages with no
CSP, or whose CSP allow-lists the host (or is permissive: `*` / `https:` scheme),
are NOT flagged.

WARN (not BLOCK): per the portfolio FP-audit discipline (sentinel-fp-audit), a new
rule starts at WARN; promote to BLOCK only after a clean portfolio sweep.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import List
from urllib.parse import urlparse

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import iter_repo_files
from sentinel.io.skip_marker import has_skip_marker


ID = "P2-csp-external-resource"
SEVERITY = Severity.WARN
SOURCE = "rules.md#html-apps (Fully offline — no external CDN)"
SCOPE = "repo"

MAX_FILE_BYTES = 5_000_000
HTML_EXCLUDE_DIRS = (".venv", "venv", "__pycache__", "node_modules", "dist",
                     "build", ".pytest_cache", "archive", "_archive", "vendor")

# The content attribute legitimately contains the OTHER quote char (CSP source
# keywords like 'self' / 'unsafe-inline'), so capture up to the matching delimiter
# via a backreference rather than a naive [^"'] class.
CSP_RE = re.compile(
    r"""<meta\b[^>]*http-equiv\s*=\s*["']Content-Security-Policy["'][^>]*?"""
    r"""content\s*=\s*(["'])(.*?)\1""",
    re.IGNORECASE | re.DOTALL,
)
SRC_RE = re.compile(r"""\bsrc\s*=\s*["'](https?://[^"'\s>]+)["']""", re.IGNORECASE)
LINK_HREF_RE = re.compile(
    r"""<link\b[^>]*\bhref\s*=\s*["'](https?://[^"'\s>]+)["']""", re.IGNORECASE
)
# A CSP whose fetch directives allow `*` or the bare `https:` scheme-source
# (NOT a concrete `https://host`) is permissive — don't second-guess it.
PERMISSIVE_RE = re.compile(
    r"(?:default-src|script-src|style-src|font-src|img-src|connect-src)"
    r"[^;]*?(?:\*|https:(?!//))",
    re.IGNORECASE,
)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    root = ctx.repo_root
    for path in iter_repo_files(root, ("*.html", "*.htm"), HTML_EXCLUDE_DIRS):
        if has_skip_marker(path) or ".backup-" in path.name:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        csps = [content for _delim, content in CSP_RE.findall(text)]
        if not csps:
            continue  # no declared policy → out of scope for this rule
        csp_blob = " ; ".join(csps)
        if PERMISSIVE_RE.search(csp_blob):
            continue  # policy intentionally allows external hosts

        rel = path.relative_to(root).as_posix()
        seen: set[tuple[str, int]] = set()
        for rx in (SRC_RE, LINK_HREF_RE):
            for m in rx.finditer(text):
                url = m.group(1)
                host = (urlparse(url).hostname or "").lower()
                if not host:
                    continue
                # Allowed if the host (or a parent-domain suffix of it) appears
                # in the CSP. Substring on host is safe: CSP source-lists carry
                # bare hostnames, so `fonts.gstatic.com` in the policy matches.
                if host in csp_blob.lower():
                    continue
                line = _line_of(text, m.start())
                key = (host, line)
                if key in seen:
                    continue
                seen.add(key)
                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=SEVERITY,
                    repo=str(root),
                    file=rel,
                    line=line,
                    detail=(
                        f"loads external resource from {host!r}, which this page's "
                        f"own Content-Security-Policy does not permit — the browser "
                        f"will block it at load (offline-contract + runtime bug)"
                    ),
                    fix_hint=(
                        "vendor the library locally (e.g. shared/vendor/) and "
                        "repoint the ref, or strip it; if the host is intended, "
                        "add it to the matching CSP fetch-directive"
                    ),
                    source=SOURCE,
                    timestamp=now,
                ))
    return verdicts
