"""P1-rules-index-integrity: WARN when a repo's `rules/_index.yaml` (the JIT
rule-routing table) points at a file or section that doesn't exist.

The index lets agents load only the rule slices a task needs
(`overmind rules --for ...`). If a slice ref like
`rules.md#Browser testing` drifts (section renamed, file moved), the JIT
loader silently returns nothing for that slice — the rule stops being
enforced without any error. This rule fails the push instead, the same way
the Sentinel rules-manifest guards its own rules.

Checks, for each `always` / per-rule `load` / `fallback` ref in
`rules/_index.yaml`:
  - the target file exists (AGENTS.md/CLAUDE.md/... at repo root; other
    `*.md` under `rules/`)
  - if the ref has a `#Section`, a markdown header with that exact title exists

WARN: a drifted index degrades context quality but doesn't corrupt code.
No-op on repos without `rules/_index.yaml`.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict

ID = "P1-rules-index-integrity"
SEVERITY = Severity.WARN
SOURCE = "AGENTS.md#context-loading-jit (JIT rule index must resolve)"
SCOPE = "repo"

_HEADER_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
_ROOT_FILES = {"AGENTS.MD", "CLAUDE.MD", "GEMINI.MD", "CODEX.MD"}


def _collect_refs(index: dict) -> list[str]:
    refs: list[str] = list(index.get("always", []) or [])
    for entry in index.get("rules", []) or []:
        refs += entry.get("load", []) or []
    refs += index.get("fallback", []) or []
    return [str(r) for r in refs]


def _section_exists(text: str, section: str) -> bool:
    want = section.strip()
    for line in text.splitlines():
        m = _HEADER_RE.match(line)
        if m and m.group(2).strip() == want:
            return True
    return False


def _resolve_file(name: str, root: Path) -> Path:
    if name.upper() in _ROOT_FILES:
        return root / name
    return root / "rules" / name


def check(ctx: RepoContext) -> List[Verdict]:
    root = ctx.repo_root
    idx_path = root / "rules" / "_index.yaml"
    if not idx_path.exists():
        return []
    try:
        import yaml  # Sentinel already depends on PyYAML for its YAML rules.
    except ImportError:
        return []
    try:
        index = yaml.safe_load(idx_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return []
    if not isinstance(index, dict):
        return []

    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    rel_idx = idx_path.relative_to(root).as_posix()
    seen: set[str] = set()
    for ref in _collect_refs(index):
        if ref in seen:
            continue
        seen.add(ref)
        fname, _, section = ref.partition("#")
        target = _resolve_file(fname.strip(), root)
        if not target.exists():
            verdicts.append(Verdict(
                rule_id=ID, severity=SEVERITY, repo=str(root), file=rel_idx, line=1,
                detail=f"_index.yaml ref '{ref}' → missing file {fname.strip()}",
                fix_hint="fix the ref or restore the file; rule files live under rules/",
                source=SOURCE, timestamp=now,
            ))
            continue
        if section:
            try:
                text = target.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if not _section_exists(text, section):
                verdicts.append(Verdict(
                    rule_id=ID, severity=SEVERITY, repo=str(root), file=rel_idx, line=1,
                    detail=f"_index.yaml ref '{ref}' → section '{section}' not found in {fname.strip()}",
                    fix_hint="update the #section to match a real markdown header, or rename the header",
                    source=SOURCE, timestamp=now,
                ))
    return verdicts
