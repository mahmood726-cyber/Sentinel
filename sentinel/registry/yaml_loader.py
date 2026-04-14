"""YAML rule loader. Parses a YAML file into a YamlRule."""
from __future__ import annotations
import fnmatch
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence, Set

import yaml

from sentinel.core import RepoContext, Severity, Verdict


REQUIRED_FIELDS = ("id", "severity", "description", "pattern", "source")

GLOBAL_EXCLUDES = (
    ".git/**",
    "node_modules/**",
    "__pycache__/**",
    "**/__pycache__/**",
    "STUCK_FAILURES.md",
    "review-findings.md",
    "**/STUCK_FAILURES.md",
    "**/review-findings.md",
)


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

        effective_exclude = list(self.exclude) + list(GLOBAL_EXCLUDES)
        tracked = _git_tracked_files(root)
        for file_path in _iter_matching_files(root, self.files, effective_exclude, tracked):
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


def _git_tracked_files(root: Path) -> Optional[Set[str]]:
    """Return set of paths (posix, relative) that git would push: tracked +
    untracked-not-ignored. Returns None if `root` is not a git repo or git is
    unavailable, in which case callers fall back to rglob (pre-gitignore
    behavior).

    Pre-push hook correctness requires this: `.gitignore`d files (e.g. build
    artifacts, logs, caches) will not be pushed, so scanning them produces
    false positives that block real work.
    """
    if not (root / ".git").is_dir():
        return None
    try:
        res = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=str(root), capture_output=True, text=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if res.returncode != 0:
        return None
    return {line.strip() for line in res.stdout.splitlines() if line.strip()}


def _iter_matching_files(
    root: Path,
    include: Sequence[str],
    exclude: Sequence[str],
    tracked: Optional[Set[str]] = None,
):
    # When we have the git-tracked set, iterate IT directly — avoids rglob'ing
    # into .venv/, node_modules/, broken symlinks, and other untracked noise
    # (Windows symlinks like .venv\lib64 raise OSError from path.is_file()).
    if tracked is not None:
        rels = tracked
    else:
        rels = _rglob_relpaths(root)

    for rel in rels:
        if not any(_fnmatch_with_doublestar(rel, pat) for pat in include):
            continue
        if any(_fnmatch_with_doublestar(rel, pat) for pat in exclude):
            continue
        path = root / rel
        try:
            if not path.is_file():
                continue
        except OSError:
            continue
        yield path


def _rglob_relpaths(root: Path) -> List[str]:
    """Defensive rglob that skips paths raising OSError (broken symlinks,
    access-denied directories on Windows)."""
    out: List[str] = []
    try:
        it = root.rglob("*")
    except OSError:
        return out
    while True:
        try:
            path = next(it)
        except StopIteration:
            break
        except OSError:
            continue
        try:
            if path.is_file():
                out.append(path.relative_to(root).as_posix())
        except OSError:
            continue
    return out


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
