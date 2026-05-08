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
from sentinel.io.paths import global_exclude_patterns


REQUIRED_FIELDS = ("id", "severity", "description", "pattern", "source", "fix_hint")

MAX_SCAN_BYTES = 5 * 1024 * 1024

# Files whose first ~1KB contains this marker are skipped by all rules.
# Intended for auto-generated files (e.g. Overmind wiki entries) and for
# files that document the very patterns Sentinel flags (rule-doc dogfooding).
# Placement: first non-frontmatter line, any comment syntax works because
# we do a literal substring match.
SKIP_FILE_MARKER = "sentinel:skip-file"
SKIP_MARKER_SCAN_BYTES = 1024

# Per-line suppression marker. Placed on the same line or the line
# immediately above the match:
#   df['x'].iloc[0]  # sentinel:skip-line P1-empty-dataframe-access
# or:
#   # sentinel:skip-line P1-empty-dataframe-access
#   df['x'].iloc[0]
# A bare `sentinel:skip-line` (no rule ID) suppresses all rules on that
# line — use sparingly. Multiple rule IDs can be space- or comma-separated:
#   # sentinel:skip-line P1-empty-dataframe-access, P0-hardcoded-local-path
# Intended for narrow false-positive cases where upstream guards are
# not visible to the pattern matcher (e.g. `if len(df) < 3: return`
# three lines before an `.iloc[0]`).
SKIP_LINE_MARKER = "sentinel:skip-line"

COMMON_EXCLUDES = (
    "tests/**",
    "**/tests/**",
    "fixtures/**",
    "**/fixtures/**",
    "conftest.py",
    "**/conftest.py",
)

GLOBAL_EXCLUDES = (
    ".git/**",
    "node_modules/**",
    "__pycache__/**",
    "**/__pycache__/**",
) + COMMON_EXCLUDES + global_exclude_patterns()


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
    # Optional guard recognition: when set, a verdict is suppressed if any
    # of the preceding `guard_lookback_lines` lines matches `guard_pattern`.
    # Used by P1-empty-dataframe-access to honour `if df.empty:` /
    # `if len(df) == 0:` guards within a small window above the access.
    # Empty string disables guard recognition (default).
    guard_pattern: str = ""
    guard_lookback_lines: int = 5
    _compiled: Optional[re.Pattern] = field(default=None, init=False, repr=False)
    _guard_compiled: Optional[re.Pattern] = field(default=None, init=False, repr=False)

    def check(self, ctx: RepoContext) -> Sequence[Verdict]:
        if self.scope == "portfolio" and ctx.is_repo_scan():
            return []
        if self.scope == "repo" and ctx.is_portfolio_scan():
            return []

        if self._compiled is None:
            self._compiled = re.compile(self.pattern)
        compiled = self._compiled
        if self.guard_pattern and self._guard_compiled is None:
            self._guard_compiled = re.compile(self.guard_pattern)
        guard_compiled = self._guard_compiled
        verdicts: List[Verdict] = []
        root = ctx.repo_root

        effective_exclude = list(self.exclude) + list(GLOBAL_EXCLUDES)
        tracked = _git_tracked_files(root)
        for file_path, rel in _iter_matching_files(root, self.files, effective_exclude, tracked):
            try:
                if file_path.stat().st_size > MAX_SCAN_BYTES:
                    continue
            except OSError:
                continue
            if _file_has_skip_marker(file_path):
                continue
            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lines = text.splitlines()
            for lineno, line in enumerate(lines, start=1):
                if compiled.search(line):
                    prev_line = lines[lineno - 2] if lineno >= 2 else ""
                    if _line_is_suppressed(line, prev_line, self.id):
                        continue
                    # Guard suppression: skip if a preceding line within the
                    # lookback window matches the rule's guard pattern.
                    if guard_compiled is not None:
                        start_idx = max(0, lineno - 1 - self.guard_lookback_lines)
                        end_idx = lineno - 1  # exclusive of the matched line itself
                        if any(
                            guard_compiled.search(lines[i])
                            for i in range(start_idx, end_idx)
                        ):
                            continue
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


def _line_is_suppressed(current_line: str, prev_line: str, rule_id: str) -> bool:
    """True if a `sentinel:skip-line` marker on current or previous line
    suppresses `rule_id`.

    Marker syntax:
      bare                  — `# sentinel:skip-line`                (all rules)
      scoped                — `# sentinel:skip-line P1-foo`          (one rule)
      multiple, separated   — `# sentinel:skip-line P1-a, P1-b`      (listed rules)
    """
    for candidate in (current_line, prev_line):
        idx = candidate.find(SKIP_LINE_MARKER)
        if idx == -1:
            continue
        after = candidate[idx + len(SKIP_LINE_MARKER):]
        tokens = [tok for tok in after.replace(",", " ").split() if tok]
        if not tokens:
            return True  # bare marker — suppress all rules on this line
        if rule_id in tokens:
            return True
    return False


def _file_has_skip_marker(file_path: Path) -> bool:
    """Return True if the file's first SKIP_MARKER_SCAN_BYTES contain the
    literal SKIP_FILE_MARKER string ('sentinel:skip-file'). Any comment
    syntax works — we do a substring match, not parsing.

    Intended uses:
      - auto-generated files (Overmind wiki entries, nightly reports)
      - files that document the very patterns Sentinel flags (rule
        documentation — dogfooding false positives)
    """
    try:
        with file_path.open("rb") as f:
            head = f.read(SKIP_MARKER_SCAN_BYTES)
    except OSError:
        return False
    try:
        text = head.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return False
    return SKIP_FILE_MARKER in text


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
            [
                "git", "-c", "core.quotePath=false",
                "ls-files", "-z",
                "--cached", "--others", "--exclude-standard",
            ],
            cwd=str(root), capture_output=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if res.returncode != 0:
        import sys
        sys.stderr.write(
            f"sentinel: git ls-files failed in {root} (rc={res.returncode}); "
            f"falling back to rglob. stderr={res.stderr[:200]!r}\n"
        )
        return None
    try:
        stdout = res.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return {entry for entry in stdout.split("\0") if entry}


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
        if ".." in rel.split("/"):
            continue
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
        yield path, rel


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

    try:
        re.compile(str(raw["pattern"]))
    except re.error as e:
        raise YamlRuleLoadError(
            f"{path}: invalid regex in 'pattern': {e}"
        ) from e

    scope = raw.get("scope", "repo")
    if scope not in ("repo", "portfolio"):
        raise YamlRuleLoadError(
            f"{path}: scope must be 'repo' or 'portfolio', got {scope!r}"
        )

    guard_pattern = str(raw.get("guard_pattern", "") or "")
    if guard_pattern:
        try:
            re.compile(guard_pattern)
        except re.error as e:
            raise YamlRuleLoadError(
                f"{path}: invalid regex in 'guard_pattern': {e}"
            ) from e
    guard_lookback_lines = int(raw.get("guard_lookback_lines", 5))
    if guard_lookback_lines < 1:
        raise YamlRuleLoadError(
            f"{path}: guard_lookback_lines must be >= 1, got {guard_lookback_lines}"
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
        guard_pattern=guard_pattern,
        guard_lookback_lines=guard_lookback_lines,
    )
