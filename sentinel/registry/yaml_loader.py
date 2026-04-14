"""YAML rule loader. Parses a YAML file into a YamlRule."""
from __future__ import annotations
import fnmatch
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Sequence

import yaml

from sentinel.core import RepoContext, Severity, Verdict


REQUIRED_FIELDS = ("id", "severity", "description", "pattern", "source")


class YamlRuleLoadError(Exception):
    """Raised when a YAML rule file is malformed or incomplete."""


def _fnmatch_with_doublestar(rel: str, pat: str) -> bool:
    """fnmatch extended to handle leading **/ so that e.g. '**/*.txt' matches
    both 'hit.txt' (root-level) and 'sub/hit.txt' (nested).

    Standard fnmatch treats '**' as a literal two-star glob, which only matches
    files one level below the '**/' prefix — it does NOT match root-level files.
    This wrapper strips leading '**/' repetitions and retries so that both cases
    resolve correctly.
    """
    if fnmatch.fnmatch(rel, pat):
        return True
    # Strip one or more leading '**/' segments and retry
    stripped = pat
    while stripped.startswith("**/"):
        stripped = stripped[3:]
    if stripped != pat and fnmatch.fnmatch(rel, stripped):
        return True
    return False


@dataclass
class YamlRule:
    id: str
    severity: Severity
    source: str
    scope: str
    description: str
    pattern: str
    files: List[str] = field(default_factory=lambda: ["**/*"])
    exclude: List[str] = field(default_factory=list)
    fix_hint: str = ""

    def check(self, ctx: RepoContext) -> Sequence[Verdict]:
        if self.scope == "portfolio" and ctx.is_repo_scan():
            return []
        if self.scope == "repo" and ctx.is_portfolio_scan():
            return []

        compiled = re.compile(self.pattern)
        verdicts: List[Verdict] = []
        root = ctx.repo_root

        for file_path in _iter_matching_files(root, self.files, self.exclude):
            rel = file_path.relative_to(root).as_posix()
            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if compiled.search(line):
                    verdicts.append(
                        Verdict(
                            rule_id=self.id,
                            severity=self.severity,
                            repo=str(root),
                            file=rel,
                            line=lineno,
                            detail=f"pattern matched: {line.strip()[:120]}",
                            fix_hint=self.fix_hint,
                            source=self.source,
                            timestamp=datetime.now(timezone.utc),
                        )
                    )
        return verdicts


def _iter_matching_files(
    root: Path, include: Sequence[str], exclude: Sequence[str]
):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if not any(_fnmatch_with_doublestar(rel, pat) for pat in include):
            continue
        if any(_fnmatch_with_doublestar(rel, pat) for pat in exclude):
            continue
        yield path


def load_yaml_rule(path: Path) -> YamlRule:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise YamlRuleLoadError(f"malformed YAML in {path}: {e}") from e
    if not isinstance(raw, dict):
        raise YamlRuleLoadError(f"{path}: root must be a mapping")

    missing = [f for f in REQUIRED_FIELDS if f not in raw]
    if missing:
        raise YamlRuleLoadError(
            f"{path}: missing required field(s): {', '.join(missing)}"
        )

    try:
        severity = Severity.from_string(raw["severity"])
    except ValueError as e:
        raise YamlRuleLoadError(f"{path}: {e}") from e

    scope = raw.get("scope", "repo")
    if scope not in ("repo", "portfolio"):
        raise YamlRuleLoadError(
            f"{path}: scope must be 'repo' or 'portfolio', got {scope!r}"
        )

    return YamlRule(
        id=str(raw["id"]),
        severity=severity,
        source=str(raw["source"]),
        scope=scope,
        description=str(raw["description"]),
        pattern=str(raw["pattern"]),
        files=list(raw.get("files", ["**/*"])),
        exclude=list(raw.get("exclude", [])),
        fix_hint=str(raw.get("fix_hint", "")),
    )
