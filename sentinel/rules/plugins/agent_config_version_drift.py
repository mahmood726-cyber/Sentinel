"""P2-agent-config-version-drift: repo-scoped.

Flags version claims in AGENTS.md / CLAUDE.md / GEMINI.md / CODEX.md that
disagree with the authoritative version in the referenced project's
pyproject.toml, package.json, or __init__.py.

Motivating incident (2026-04-15): AGENTS.md claimed Overmind v2.1.0 while
pyproject.toml had 3.1.0 for 7+ days. Manual audit caught it; this rule
catches it at next push.

Detection: matches `**<Name>** (`<Path>`, v<X.Y.Z>...)` in the config files.
Validation: resolves `<Path>` → pyproject.toml / package.json / subpkg
__init__.py in that priority order. If none found, skips (can't verify).

Severity: WARN. Version drift during an in-progress bump is normal and
shouldn't block pushes — but it SHOULD surface in sentinel-findings.md so
it doesn't stay stale for a week (as the motivating incident did).
"""
from __future__ import annotations
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from sentinel.core import RepoContext, Severity, Verdict


ID = "P2-agent-config-version-drift"
SEVERITY = Severity.WARN
SOURCE = "lessons.md#agent-workflow"
SCOPE = "repo"

_CONFIG_FILES = ("AGENTS.md", "CLAUDE.md", "GEMINI.md", "CODEX.md")

# Matches: `**Name** (`C:\path\`, vX.Y.Z...)` with anything between the
# closing backtick of the path and the `v`. Name stops at first `*`.
_CLAIM_RE = re.compile(
    r"\*\*([^*]+?)\*\*\s*\(\s*`([A-Za-z]:[\\/][^`]+)`[^)]*?v(\d+\.\d+\.\d+)"
)


def _authoritative_version(proj_path: Path) -> Optional[str]:
    """Return the authoritative version from proj_path, or None if no
    recognized source file is present."""
    pyproject = proj_path / "pyproject.toml"
    if pyproject.is_file():
        try:
            content = pyproject.read_text(encoding="utf-8", errors="replace")
        except OSError:
            content = ""
        m = re.search(r'^\s*version\s*=\s*"([^"]+)"', content, re.MULTILINE)
        if m:
            return m.group(1)

    package_json = proj_path / "package.json"
    if package_json.is_file():
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "version" in data:
                return str(data["version"])
        except (OSError, json.JSONDecodeError):
            pass

    try:
        children = list(proj_path.iterdir())
    except OSError:
        children = []
    for item in children:
        if not item.is_dir():
            continue
        init_py = item / "__init__.py"
        if not init_py.is_file():
            continue
        try:
            text = init_py.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', text)
        if m:
            return m.group(1)

    return None


def check(ctx: RepoContext) -> List[Verdict]:
    verdicts: List[Verdict] = []
    now = datetime.now(timezone.utc)
    root = ctx.repo_root

    for name in _CONFIG_FILES:
        config = root / name
        if not config.is_file():
            continue
        try:
            text = config.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            m = _CLAIM_RE.search(line)
            if not m:
                continue
            proj_name = m.group(1).strip()
            proj_path_str = m.group(2).rstrip("\\/")
            claimed = m.group(3)
            proj_path = Path(proj_path_str)
            if not proj_path.is_dir():
                continue
            actual = _authoritative_version(proj_path)
            if actual is None:
                continue
            if actual == claimed:
                continue
            verdicts.append(
                Verdict(
                    rule_id=ID,
                    severity=SEVERITY,
                    repo=str(root),
                    file=name,
                    line=lineno,
                    detail=(
                        f"{name} claims {proj_name} v{claimed} but "
                        f"{proj_path_str} authoritative version is v{actual}"
                    ),
                    fix_hint=(
                        f"Either update {name} to v{actual}, OR bump the "
                        f"authoritative source in {proj_path_str} to v{claimed} "
                        f"if the config reflects an intentional release claim."
                    ),
                    source=SOURCE,
                    timestamp=now,
                )
            )
    return verdicts
