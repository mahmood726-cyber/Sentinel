"""P1-blueprint-implementation-match: repo-scoped.

Fires only when `blueprint.json` is present in the repo root. Parses the
blueprint's declared ids from `inputs[].id`, `ui_sections[].id`, and
`outputs[].id`, then checks that each one appears as a DOM attribute
(id="<id>", class="<id>", data-*="<id>") in at least one `.html` file.

Motivating workflow (2026-04-18): the `/spec-html` slash command builds
single-file scientific HTML apps from a spec-first 4-stage pipeline,
emitting `blueprint.json` as a machine-readable intent contract at
Stage 1. Sentinel verifies at push time that shipped HTML still matches
the declared contract — catches scope creep and drift before the
dashboard ships.

Severity: WARN (not BLOCK). Blueprint drift during an in-progress edit
shouldn't kill a push; but it should surface in sentinel-findings.md so
it doesn't stay stale.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Set

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import HTML_EXCLUDE_DIRS, iter_repo_files


ID = "P1-blueprint-implementation-match"
SEVERITY = Severity.WARN
SOURCE = "lessons.md#html-apps"
SCOPE = "repo"

_DOM_TOKEN_RE = re.compile(
    r'(?:id|class|data-[a-z0-9-]+)\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def _collect_blueprint_ids(data: dict) -> Set[str]:
    ids: Set[str] = set()
    for key in ("inputs", "outputs"):
        for item in data.get(key, []) or []:
            if isinstance(item, dict):
                item_id = item.get("id")
                if isinstance(item_id, str) and item_id:
                    ids.add(item_id)
    for item in data.get("ui_sections", []) or []:
        if isinstance(item, dict):
            item_id = item.get("id")
            if isinstance(item_id, str) and item_id:
                ids.add(item_id)
        elif isinstance(item, str) and item:
            ids.add(item)
    return ids


def _collect_dom_tokens(html_paths: List[Path]) -> Set[str]:
    tokens: Set[str] = set()
    for hp in html_paths:
        try:
            text = hp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in _DOM_TOKEN_RE.finditer(text):
            for token in match.group(1).split():
                if token:
                    tokens.add(token)
    return tokens


def check(ctx: RepoContext) -> List[Verdict]:
    blueprint = ctx.repo_root / "blueprint.json"
    now = datetime.now(timezone.utc)
    repo_prefix = str(ctx.repo_root)

    if not blueprint.exists():
        return []

    if not blueprint.is_file():
        return [Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=repo_prefix,
            file="blueprint.json",
            line=None,
            detail="blueprint.json path exists but is not a regular file (directory or symlink?)",
            fix_hint="remove the directory or symlink named 'blueprint.json' or rename it",
            source=SOURCE,
            timestamp=now,
        )]

    try:
        raw = blueprint.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as e:
        return [Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=repo_prefix,
            file="blueprint.json",
            line=None,
            detail=f"blueprint.json unreadable ({type(e).__name__})",
            fix_hint="repair blueprint.json so implementation match can verify",
            source=SOURCE,
            timestamp=now,
        )]

    if not isinstance(data, dict):
        return [Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=repo_prefix,
            file="blueprint.json",
            line=None,
            detail="blueprint.json must be a JSON object at the top level",
            fix_hint="blueprint.json must start with { and end with } (a JSON object, not an array or string)",
            source=SOURCE,
            timestamp=now,
        )]

    declared = _collect_blueprint_ids(data)
    if not declared:
        return []

    html_files = sorted(iter_repo_files(ctx.repo_root, "*.html", HTML_EXCLUDE_DIRS))

    if not html_files:
        return [Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=repo_prefix,
            file="blueprint.json",
            line=None,
            detail=(
                f"blueprint.json declares {len(declared)} id(s) but no "
                ".html file exists yet — the implementation stage has not run"
            ),
            fix_hint=(
                "generate the HTML app from the blueprint, or remove "
                "blueprint.json if the spec is no longer active"
            ),
            source=SOURCE,
            timestamp=now,
        )]

    dom = _collect_dom_tokens(html_files)
    missing = sorted(declared - dom)
    if not missing:
        return []

    preview = ", ".join(missing[:10])
    suffix = f" (+{len(missing) - 10} more)" if len(missing) > 10 else ""

    return [Verdict(
        rule_id=ID,
        severity=SEVERITY,
        repo=repo_prefix,
        file="blueprint.json",
        line=None,
        detail=(
            f"blueprint.json declares {len(missing)} id(s) not found in "
            f"any .html file: {preview}{suffix}"
        ),
        fix_hint=(
            "either implement the missing DOM element(s) in the HTML "
            "app or remove the stale id from blueprint.json"
        ),
        source=SOURCE,
        timestamp=now,
    )]
