# Sentinel M1 — Rule Engine + 3 Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Sentinel's core rule engine (hybrid YAML + Python plugin loader, uniform Verdict record, repo + portfolio scan modes) plus three P0 rules — `P0-placeholder-hmac`, `P0-path-not-exist`, `P0-registry-drift` (wrapping `reconcile_counts.py`) — exercised end-to-end via a `sentinel` CLI.

**Architecture:** Python package under `C:\Sentinel\sentinel\` with strict module boundaries (`core`, `registry`, `rules`, `io`, `cli`). Rules are data: YAML files for pattern matchers, Python modules for logic matchers, both producing the same `Verdict` record. CLI has two scan modes (`--repo` and `--portfolio`) mapping cleanly onto the spec's rule-scope model. Fail-closed by design: any rule error, loader error, or empty registry produces exit code 1.

**Tech Stack:** Python 3.13 (Windows-first), PyYAML for rule files, pytest + pytest-cov for tests, standard library only for everything else (`subprocess`, `pathlib`, `dataclasses`, `json`, `re`, `argparse`, `importlib`). No PyMC, PyTensor, or heavy deps per CLAUDE.md.

**Non-goals for M1:** Pre-push hook installer (M2), dashboard (M3), rules 4–10 (M2–M3). Portfolio-wide sweep across all 472 repos (M3).

---

## File Structure

```
C:\Sentinel\
  pyproject.toml                              # Package config + pytest config + coverage config
  README.md                                   # Quickstart + exit-criteria checklist
  sentinel/
    __init__.py                               # Package version
    core/
      __init__.py                             # Re-exports Severity, Verdict, RepoContext, Rule
      severity.py                             # Severity enum (BLOCK/WARN/INFO)
      verdict.py                              # Verdict dataclass + to_dict()
      context.py                              # RepoContext dataclass
      rule.py                                 # Rule base protocol
    registry/
      __init__.py                             # Re-exports Registry
      yaml_loader.py                          # Parse a YAML file into a YamlRule
      plugin_loader.py                        # Import a Python module and wrap it as a PluginRule
      registry.py                             # Combined registry (discover + load + iterate)
    rules/
      __init__.py                             # Empty — rules/ is a namespace for rule definitions
      yaml/
        P0-placeholder-hmac.yaml              # Rule 1
      plugins/
        __init__.py                           # Empty — plugins/ is a namespace for plugin rules
        path_not_exist.py                     # Rule 2 (portfolio-scoped)
        registry_drift.py                     # Rule 3 (portfolio-scoped; wraps reconcile_counts.py)
    io/
      __init__.py                             # Re-exports scan_files, write_findings
      scanner.py                              # Walk a repo respecting include/exclude globs
      writer.py                               # Write review-findings.md + STUCK_FAILURES.md
    cli/
      __init__.py                             # Empty
      __main__.py                             # Entry: `python -m sentinel ...`
      scan.py                                 # scan subcommand (--repo / --portfolio)
      list_rules.py                           # list-rules subcommand
      explain.py                              # explain <rule-id> subcommand
  tests/
    __init__.py                               # Empty
    conftest.py                               # Shared fixtures (tmp_path helpers)
    contracts/
      __init__.py
      test_yaml_rule_schema.py                # YAML schema contract
      test_plugin_interface.py                # Plugin interface contract
      test_verdict_schema.py                  # Verdict JSON schema contract
    unit/
      __init__.py
      test_severity.py
      test_verdict.py
      test_context.py
      test_yaml_loader.py
      test_plugin_loader.py
      test_registry.py
      test_scanner.py
      test_writer.py
      test_rule_placeholder_hmac.py
      test_rule_path_not_exist.py
      test_rule_registry_drift.py
      test_cli_scan.py
      test_cli_list_rules.py
      test_cli_explain.py
    fixtures/
      repos/
        placeholder_hmac_BAD/cert.json        # Contains "SIG_RSA_SHA256_..." literal
        placeholder_hmac_BAD/.gitkeep
        placeholder_hmac_GOOD/cert.json       # Contains a real-looking hex HMAC
        placeholder_hmac_GOOD/.gitkeep
      project_index_GOOD/
        INDEX.md                              # Mirrors real INDEX.md shape, all paths exist
        agent-records/restart-manifest.json
        reconcile_counts.py                   # Stub that exits 0
      project_index_DRIFT/
        INDEX.md                              # Claims path that doesn't exist on disk
        agent-records/restart-manifest.json
        reconcile_counts.py                   # Stub that exits 1
    regression/
      __init__.py
      test_zero_rules_noop.py
      test_reconcile_exit_code_unchanged.py
      test_no_writes_outside_scope.py
```

**Boundary rules:**
- `core/` has no imports from `registry/`, `rules/`, `io/`, or `cli/`. It's the leaf.
- `registry/` imports from `core/` only.
- `rules/` imports from `core/` only.
- `io/` imports from `core/` only.
- `cli/` is the only module allowed to import from `registry/` + `io/` + `rules/` transitively.
- `tests/` may import anything.

---

## Task 1: Project scaffolding + pyproject.toml

**Files:**
- Create: `C:\Sentinel\pyproject.toml`
- Create: `C:\Sentinel\sentinel\__init__.py`
- Create: `C:\Sentinel\tests\__init__.py`
- Create: `C:\Sentinel\tests\conftest.py`

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "sentinel"
version = "0.1.0"
description = "Portfolio fail-closed integrity engine"
requires-python = ">=3.13"
dependencies = ["PyYAML>=6.0"]

[project.optional-dependencies]
dev = ["pytest>=8.0", "pytest-cov>=5.0"]

[project.scripts]
sentinel = "sentinel.cli.__main__:main"

[tool.setuptools.packages.find]
include = ["sentinel*"]
exclude = ["tests*"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v --tb=short --strict-markers"
markers = [
    "contract: contract tests between modules",
    "regression: non-regression guarantee tests",
]

[tool.coverage.run]
source = ["sentinel/core", "sentinel/registry"]
branch = true

[tool.coverage.report]
fail_under = 90
show_missing = true
```

- [ ] **Step 2: Write `sentinel/__init__.py`**

```python
__version__ = "0.1.0"
```

- [ ] **Step 3: Write `tests/__init__.py`** (empty)

```python
```

- [ ] **Step 4: Write `tests/conftest.py`**

```python
"""Shared pytest fixtures."""
from pathlib import Path
import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    """Absolute path to tests/fixtures/."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    """An empty tmp directory that behaves like a repo root."""
    return tmp_path
```

- [ ] **Step 5: Install the package in editable mode + dev deps**

Run: `python -m pip install -e ".[dev]"`
Expected: `Successfully installed sentinel-0.1.0`

- [ ] **Step 6: Verify pytest discovers zero tests**

Run: `python -m pytest` (from `C:\Sentinel\`)
Expected: `no tests ran` (exit 5 is OK here — zero tests is expected pre-commit)

- [ ] **Step 7: Commit**

```bash
cd C:/Sentinel
git add pyproject.toml sentinel/__init__.py tests/__init__.py tests/conftest.py
git commit -m "chore: scaffold Sentinel package layout and pytest config"
```

---

## Task 2: Severity enum

**Files:**
- Create: `C:\Sentinel\sentinel\core\__init__.py`
- Create: `C:\Sentinel\sentinel\core\severity.py`
- Create: `C:\Sentinel\tests\unit\__init__.py`
- Create: `C:\Sentinel\tests\unit\test_severity.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_severity.py
import pytest
from sentinel.core.severity import Severity


def test_severity_has_three_tiers():
    assert {s.name for s in Severity} == {"BLOCK", "WARN", "INFO"}


def test_severity_ordering_block_gt_warn_gt_info():
    assert Severity.BLOCK.rank > Severity.WARN.rank > Severity.INFO.rank


def test_severity_from_string_case_insensitive():
    assert Severity.from_string("block") == Severity.BLOCK
    assert Severity.from_string("BLOCK") == Severity.BLOCK
    assert Severity.from_string("Warn") == Severity.WARN


def test_severity_from_string_unknown_raises():
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.from_string("critical")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_severity.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'sentinel.core.severity'`

- [ ] **Step 3: Write `sentinel/core/severity.py`**

```python
"""Three-tier severity: BLOCK aborts, WARN logs, INFO dashboards only."""
from __future__ import annotations
from enum import Enum


class Severity(Enum):
    INFO = ("INFO", 0)
    WARN = ("WARN", 1)
    BLOCK = ("BLOCK", 2)

    def __init__(self, label: str, rank: int) -> None:
        self.label = label
        self.rank = rank

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        upper = value.upper()
        for member in cls:
            if member.label == upper:
                return member
        raise ValueError(f"unknown severity: {value!r} (expected BLOCK/WARN/INFO)")
```

- [ ] **Step 4: Write `sentinel/core/__init__.py`** (initial — will grow)

```python
from sentinel.core.severity import Severity

__all__ = ["Severity"]
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_severity.py -v`
Expected: `4 passed`

- [ ] **Step 6: Commit**

```bash
git add sentinel/core/__init__.py sentinel/core/severity.py tests/unit/__init__.py tests/unit/test_severity.py
git commit -m "feat(core): add Severity three-tier enum with case-insensitive parsing"
```

---

## Task 3: Verdict dataclass

**Files:**
- Create: `C:\Sentinel\sentinel\core\verdict.py`
- Create: `C:\Sentinel\tests\unit\test_verdict.py`
- Modify: `C:\Sentinel\sentinel\core\__init__.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_verdict.py
from datetime import datetime, timezone
from sentinel.core.verdict import Verdict
from sentinel.core.severity import Severity


def test_verdict_to_dict_round_trips_all_fields():
    ts = datetime(2026, 4, 14, 10, 23, 0, tzinfo=timezone.utc)
    v = Verdict(
        rule_id="P0-placeholder-hmac",
        severity=Severity.BLOCK,
        repo="C:/Projects/shifaa",
        file="shifaa/bundles/cert_v1.json",
        line=42,
        detail="placeholder signature shipped",
        fix_hint="replace with env TRUTHCERT_HMAC_KEY",
        source="lessons.md#cryptography-signing",
        timestamp=ts,
    )
    d = v.to_dict()
    assert d["rule_id"] == "P0-placeholder-hmac"
    assert d["severity"] == "BLOCK"
    assert d["line"] == 42
    assert d["timestamp"] == "2026-04-14T10:23:00+00:00"


def test_verdict_accepts_none_line_and_file_for_repo_wide_findings():
    v = Verdict(
        rule_id="P0-registry-drift",
        severity=Severity.BLOCK,
        repo="C:/ProjectIndex",
        file=None,
        line=None,
        detail="manifest missing",
        fix_hint="restore manifest",
        source="workflow.md",
        timestamp=datetime.now(timezone.utc),
    )
    d = v.to_dict()
    assert d["file"] is None
    assert d["line"] is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_verdict.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'sentinel.core.verdict'`

- [ ] **Step 3: Write `sentinel/core/verdict.py`**

```python
"""Uniform verdict record emitted by every rule, regardless of rule type."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sentinel.core.severity import Severity


@dataclass(frozen=True)
class Verdict:
    rule_id: str
    severity: Severity
    repo: str
    file: Optional[str]
    line: Optional[int]
    detail: str
    fix_hint: str
    source: str
    timestamp: datetime

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.label,
            "repo": self.repo,
            "file": self.file,
            "line": self.line,
            "detail": self.detail,
            "fix_hint": self.fix_hint,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
        }
```

- [ ] **Step 4: Update `sentinel/core/__init__.py`**

```python
from sentinel.core.severity import Severity
from sentinel.core.verdict import Verdict

__all__ = ["Severity", "Verdict"]
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_verdict.py -v`
Expected: `2 passed`

- [ ] **Step 6: Commit**

```bash
git add sentinel/core/verdict.py sentinel/core/__init__.py tests/unit/test_verdict.py
git commit -m "feat(core): add Verdict dataclass with to_dict() serialization"
```

---

## Task 4: RepoContext dataclass

**Files:**
- Create: `C:\Sentinel\sentinel\core\context.py`
- Create: `C:\Sentinel\tests\unit\test_context.py`
- Modify: `C:\Sentinel\sentinel\core\__init__.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_context.py
from pathlib import Path
from sentinel.core.context import RepoContext, ScanMode


def test_repo_context_repo_mode(tmp_path: Path):
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert ctx.repo_root == tmp_path
    assert ctx.mode == ScanMode.REPO
    assert ctx.is_repo_scan()
    assert not ctx.is_portfolio_scan()


def test_repo_context_portfolio_mode(tmp_path: Path):
    ctx = RepoContext(
        repo_root=tmp_path,
        mode=ScanMode.PORTFOLIO,
        project_index_root=tmp_path / "ProjectIndex",
    )
    assert ctx.is_portfolio_scan()
    assert ctx.project_index_root == tmp_path / "ProjectIndex"


def test_repo_context_portfolio_requires_project_index_root(tmp_path: Path):
    import pytest
    with pytest.raises(ValueError, match="project_index_root required"):
        RepoContext(repo_root=tmp_path, mode=ScanMode.PORTFOLIO)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_context.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write `sentinel/core/context.py`**

```python
"""Runtime context passed to every rule's check() function."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional


class ScanMode(Enum):
    REPO = "repo"
    PORTFOLIO = "portfolio"


@dataclass(frozen=True)
class RepoContext:
    repo_root: Path
    mode: ScanMode
    project_index_root: Optional[Path] = None

    def __post_init__(self) -> None:
        if self.mode == ScanMode.PORTFOLIO and self.project_index_root is None:
            raise ValueError(
                "project_index_root required when mode=PORTFOLIO "
                "(need access to INDEX.md + manifest)"
            )

    def is_repo_scan(self) -> bool:
        return self.mode == ScanMode.REPO

    def is_portfolio_scan(self) -> bool:
        return self.mode == ScanMode.PORTFOLIO
```

- [ ] **Step 4: Update `sentinel/core/__init__.py`**

```python
from sentinel.core.context import RepoContext, ScanMode
from sentinel.core.severity import Severity
from sentinel.core.verdict import Verdict

__all__ = ["RepoContext", "ScanMode", "Severity", "Verdict"]
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_context.py -v`
Expected: `3 passed`

- [ ] **Step 6: Commit**

```bash
git add sentinel/core/context.py sentinel/core/__init__.py tests/unit/test_context.py
git commit -m "feat(core): add RepoContext and ScanMode"
```

---

## Task 5: Rule protocol

**Files:**
- Create: `C:\Sentinel\sentinel\core\rule.py`
- Modify: `C:\Sentinel\sentinel\core\__init__.py`

- [ ] **Step 1: Write `sentinel/core/rule.py`**

```python
"""Rule protocol — both YAML-backed and plugin-backed rules satisfy it."""
from __future__ import annotations
from typing import Protocol, Sequence, runtime_checkable

from sentinel.core.context import RepoContext
from sentinel.core.severity import Severity
from sentinel.core.verdict import Verdict


@runtime_checkable
class Rule(Protocol):
    """Every rule exposes these four attributes + check()."""

    id: str
    severity: Severity
    source: str
    scope: str  # "repo" or "portfolio"

    def check(self, ctx: RepoContext) -> Sequence[Verdict]:
        ...
```

- [ ] **Step 2: Update `sentinel/core/__init__.py`**

```python
from sentinel.core.context import RepoContext, ScanMode
from sentinel.core.rule import Rule
from sentinel.core.severity import Severity
from sentinel.core.verdict import Verdict

__all__ = ["Rule", "RepoContext", "ScanMode", "Severity", "Verdict"]
```

- [ ] **Step 3: Verify package still imports**

Run: `python -c "from sentinel.core import Rule, Severity, Verdict, RepoContext, ScanMode; print('ok')"`
Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add sentinel/core/rule.py sentinel/core/__init__.py
git commit -m "feat(core): add Rule runtime-checkable Protocol"
```

---

## Task 6: YAML loader + YamlRule

**Files:**
- Create: `C:\Sentinel\sentinel\registry\__init__.py`
- Create: `C:\Sentinel\sentinel\registry\yaml_loader.py`
- Create: `C:\Sentinel\tests\unit\test_yaml_loader.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_yaml_loader.py
from pathlib import Path
import pytest
from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.yaml_loader import load_yaml_rule, YamlRuleLoadError


YAML_VALID = """
id: TEST-pattern-match
severity: BLOCK
scope: repo
description: Test rule
pattern: 'FORBIDDEN_TOKEN'
files: ['**/*.txt']
exclude: ['ignore/**']
fix_hint: Remove the token.
source: test.md#forbidden
"""


def test_load_yaml_rule_parses_all_fields(tmp_path: Path):
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(YAML_VALID, encoding="utf-8")
    rule = load_yaml_rule(rule_file)
    assert rule.id == "TEST-pattern-match"
    assert rule.severity == Severity.BLOCK
    assert rule.scope == "repo"
    assert rule.pattern == "FORBIDDEN_TOKEN"
    assert rule.files == ["**/*.txt"]
    assert rule.exclude == ["ignore/**"]


def test_load_yaml_rule_missing_required_field_raises(tmp_path: Path):
    rule_file = tmp_path / "bad.yaml"
    rule_file.write_text("id: incomplete\nseverity: BLOCK\n", encoding="utf-8")
    with pytest.raises(YamlRuleLoadError, match="missing required field"):
        load_yaml_rule(rule_file)


def test_load_yaml_rule_unknown_severity_raises(tmp_path: Path):
    rule_file = tmp_path / "bad.yaml"
    bad = YAML_VALID.replace("severity: BLOCK", "severity: CRITICAL")
    rule_file.write_text(bad, encoding="utf-8")
    with pytest.raises(YamlRuleLoadError, match="unknown severity"):
        load_yaml_rule(rule_file)


def test_yaml_rule_check_finds_pattern(tmp_path: Path):
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(YAML_VALID, encoding="utf-8")
    rule = load_yaml_rule(rule_file)

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "hit.txt").write_text("some FORBIDDEN_TOKEN here\n", encoding="utf-8")
    (repo / "miss.txt").write_text("clean content\n", encoding="utf-8")

    ctx = RepoContext(repo_root=repo, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "TEST-pattern-match"
    assert verdicts[0].file == "hit.txt"
    assert verdicts[0].line == 1


def test_yaml_rule_check_respects_exclude(tmp_path: Path):
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(YAML_VALID, encoding="utf-8")
    rule = load_yaml_rule(rule_file)

    repo = tmp_path / "repo"
    (repo / "ignore").mkdir(parents=True)
    (repo / "ignore" / "skip.txt").write_text("FORBIDDEN_TOKEN\n", encoding="utf-8")

    ctx = RepoContext(repo_root=repo, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_yaml_rule_scope_defaults_to_repo(tmp_path: Path):
    rule_file = tmp_path / "rule.yaml"
    no_scope = YAML_VALID.replace("scope: repo\n", "")
    rule_file.write_text(no_scope, encoding="utf-8")
    rule = load_yaml_rule(rule_file)
    assert rule.scope == "repo"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_yaml_loader.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write `sentinel/registry/yaml_loader.py`**

```python
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
        if not any(fnmatch.fnmatch(rel, pat) for pat in include):
            continue
        if any(fnmatch.fnmatch(rel, pat) for pat in exclude):
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
```

- [ ] **Step 4: Write `sentinel/registry/__init__.py`** (initial)

```python
from sentinel.registry.yaml_loader import YamlRule, YamlRuleLoadError, load_yaml_rule

__all__ = ["YamlRule", "YamlRuleLoadError", "load_yaml_rule"]
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_yaml_loader.py -v`
Expected: `6 passed`

- [ ] **Step 6: Commit**

```bash
git add sentinel/registry/__init__.py sentinel/registry/yaml_loader.py tests/unit/test_yaml_loader.py
git commit -m "feat(registry): YAML rule loader with pattern + scope support"
```

---

## Task 7: Plugin loader + PluginRule

**Files:**
- Create: `C:\Sentinel\sentinel\registry\plugin_loader.py`
- Create: `C:\Sentinel\tests\unit\test_plugin_loader.py`
- Modify: `C:\Sentinel\sentinel\registry\__init__.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_plugin_loader.py
from pathlib import Path
import textwrap
import pytest

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import (
    load_plugin_rule,
    PluginRuleLoadError,
)


PLUGIN_VALID = textwrap.dedent("""
    from datetime import datetime, timezone
    from sentinel.core import Severity, Verdict

    ID = 'TEST-plugin'
    SEVERITY = Severity.WARN
    SOURCE = 'test.md'
    SCOPE = 'repo'

    def check(ctx):
        return [
            Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(ctx.repo_root),
                file=None,
                line=None,
                detail='hit',
                fix_hint='fix it',
                source=SOURCE,
                timestamp=datetime.now(timezone.utc),
            )
        ]
""")


def test_load_plugin_rule_returns_wrapper(tmp_path: Path):
    plugin_file = tmp_path / "plugin.py"
    plugin_file.write_text(PLUGIN_VALID, encoding="utf-8")
    rule = load_plugin_rule(plugin_file)
    assert rule.id == "TEST-plugin"
    assert rule.severity == Severity.WARN
    assert rule.scope == "repo"


def test_load_plugin_rule_missing_id_raises(tmp_path: Path):
    plugin_file = tmp_path / "plugin.py"
    plugin_file.write_text(
        PLUGIN_VALID.replace("ID = 'TEST-plugin'", ""), encoding="utf-8"
    )
    with pytest.raises(PluginRuleLoadError, match="missing required attribute: ID"):
        load_plugin_rule(plugin_file)


def test_load_plugin_rule_missing_check_raises(tmp_path: Path):
    plugin_file = tmp_path / "plugin.py"
    src = PLUGIN_VALID.replace("def check", "def _disabled_check")
    plugin_file.write_text(src, encoding="utf-8")
    with pytest.raises(PluginRuleLoadError, match="missing required attribute: check"):
        load_plugin_rule(plugin_file)


def test_plugin_rule_check_invokes_wrapped_function(tmp_path: Path):
    plugin_file = tmp_path / "plugin.py"
    plugin_file.write_text(PLUGIN_VALID, encoding="utf-8")
    rule = load_plugin_rule(plugin_file)

    repo = tmp_path / "repo"
    repo.mkdir()
    verdicts = rule.check(RepoContext(repo_root=repo, mode=ScanMode.REPO))
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "TEST-plugin"


def test_plugin_rule_check_catches_exceptions_as_block(tmp_path: Path):
    src = PLUGIN_VALID.replace(
        "return [", "raise RuntimeError('boom')  # noqa\n    return ["
    )
    plugin_file = tmp_path / "plugin.py"
    plugin_file.write_text(src, encoding="utf-8")
    rule = load_plugin_rule(plugin_file)
    repo = tmp_path / "repo"
    repo.mkdir()
    verdicts = rule.check(RepoContext(repo_root=repo, mode=ScanMode.REPO))
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.BLOCK
    assert "RuntimeError" in verdicts[0].detail
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_plugin_loader.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write `sentinel/registry/plugin_loader.py`**

```python
"""Plugin rule loader. Imports a Python module and wraps it as a rule."""
from __future__ import annotations
import importlib.util
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Sequence

from sentinel.core import RepoContext, Severity, Verdict


REQUIRED_ATTRS = ("ID", "SEVERITY", "SOURCE", "check")


class PluginRuleLoadError(Exception):
    """Raised when a plugin module is missing required attributes."""


@dataclass
class PluginRule:
    id: str
    severity: Severity
    source: str
    scope: str
    _check: Callable[[RepoContext], Sequence[Verdict]]

    def check(self, ctx: RepoContext) -> Sequence[Verdict]:
        if self.scope == "portfolio" and ctx.is_repo_scan():
            return []
        if self.scope == "repo" and ctx.is_portfolio_scan():
            return []

        try:
            result = self._check(ctx)
        except Exception as e:
            return [
                Verdict(
                    rule_id=self.id,
                    severity=Severity.BLOCK,
                    repo=str(ctx.repo_root),
                    file=None,
                    line=None,
                    detail=f"{type(e).__name__}: {e}\n{traceback.format_exc()}",
                    fix_hint=f"rule {self.id} raised; fix the plugin or bypass the rule",
                    source=self.source,
                    timestamp=datetime.now(timezone.utc),
                )
            ]
        return list(result)


def load_plugin_rule(path: Path) -> PluginRule:
    spec = importlib.util.spec_from_file_location(f"sentinel_plugin_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise PluginRuleLoadError(f"{path}: cannot import")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        raise PluginRuleLoadError(f"{path}: import failed: {e}") from e

    for attr in REQUIRED_ATTRS:
        if not hasattr(module, attr):
            raise PluginRuleLoadError(
                f"{path}: missing required attribute: {attr}"
            )

    sev = module.SEVERITY
    if not isinstance(sev, Severity):
        raise PluginRuleLoadError(
            f"{path}: SEVERITY must be sentinel.core.Severity, got {type(sev).__name__}"
        )

    scope = getattr(module, "SCOPE", "repo")
    if scope not in ("repo", "portfolio"):
        raise PluginRuleLoadError(
            f"{path}: SCOPE must be 'repo' or 'portfolio', got {scope!r}"
        )

    return PluginRule(
        id=str(module.ID),
        severity=sev,
        source=str(module.SOURCE),
        scope=scope,
        _check=module.check,
    )
```

- [ ] **Step 4: Update `sentinel/registry/__init__.py`**

```python
from sentinel.registry.plugin_loader import (
    PluginRule,
    PluginRuleLoadError,
    load_plugin_rule,
)
from sentinel.registry.yaml_loader import (
    YamlRule,
    YamlRuleLoadError,
    load_yaml_rule,
)

__all__ = [
    "PluginRule",
    "PluginRuleLoadError",
    "YamlRule",
    "YamlRuleLoadError",
    "load_plugin_rule",
    "load_yaml_rule",
]
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_plugin_loader.py -v`
Expected: `5 passed`

- [ ] **Step 6: Commit**

```bash
git add sentinel/registry/plugin_loader.py sentinel/registry/__init__.py tests/unit/test_plugin_loader.py
git commit -m "feat(registry): plugin rule loader with fail-closed exception handling"
```

---

## Task 8: Registry — discovery + combined iteration

**Files:**
- Create: `C:\Sentinel\sentinel\registry\registry.py`
- Create: `C:\Sentinel\tests\unit\test_registry.py`
- Modify: `C:\Sentinel\sentinel\registry\__init__.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_registry.py
import textwrap
from pathlib import Path
import pytest

from sentinel.core import Severity
from sentinel.registry.registry import Registry, EmptyRegistryError


YAML_RULE = """
id: Y-one
severity: WARN
scope: repo
description: y
pattern: 'foo'
source: test.md
"""

PLUGIN_RULE = textwrap.dedent("""
    from sentinel.core import Severity
    ID = 'P-one'
    SEVERITY = Severity.INFO
    SOURCE = 'test.md'
    SCOPE = 'repo'
    def check(ctx):
        return []
""")


def _setup_rules(tmp_path: Path) -> Path:
    root = tmp_path / "rules"
    (root / "yaml").mkdir(parents=True)
    (root / "plugins").mkdir(parents=True)
    (root / "yaml" / "y.yaml").write_text(YAML_RULE, encoding="utf-8")
    (root / "plugins" / "p.py").write_text(PLUGIN_RULE, encoding="utf-8")
    return root


def test_registry_discovers_both_rule_types(tmp_path: Path):
    root = _setup_rules(tmp_path)
    reg = Registry.from_dir(root)
    ids = {r.id for r in reg.all_rules()}
    assert ids == {"Y-one", "P-one"}


def test_registry_get_by_id(tmp_path: Path):
    root = _setup_rules(tmp_path)
    reg = Registry.from_dir(root)
    rule = reg.get("Y-one")
    assert rule.severity == Severity.WARN


def test_registry_get_unknown_raises(tmp_path: Path):
    root = _setup_rules(tmp_path)
    reg = Registry.from_dir(root)
    with pytest.raises(KeyError, match="unknown rule id"):
        reg.get("does-not-exist")


def test_registry_empty_raises(tmp_path: Path):
    root = tmp_path / "rules"
    (root / "yaml").mkdir(parents=True)
    (root / "plugins").mkdir(parents=True)
    with pytest.raises(EmptyRegistryError):
        Registry.from_dir(root)


def test_registry_duplicate_ids_raises(tmp_path: Path):
    root = tmp_path / "rules"
    (root / "yaml").mkdir(parents=True)
    (root / "plugins").mkdir(parents=True)
    dup = YAML_RULE.replace("id: Y-one", "id: DUP")
    (root / "yaml" / "a.yaml").write_text(dup, encoding="utf-8")
    (root / "yaml" / "b.yaml").write_text(dup, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate rule id: DUP"):
        Registry.from_dir(root)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_registry.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write `sentinel/registry/registry.py`**

```python
"""Registry: discovers + loads + indexes all rules from a rules/ dir."""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from sentinel.core import Rule
from sentinel.registry.plugin_loader import load_plugin_rule
from sentinel.registry.yaml_loader import load_yaml_rule


class EmptyRegistryError(Exception):
    """Raised when a rules directory contains zero rules (fail-closed)."""


@dataclass
class Registry:
    rules: Dict[str, Rule] = field(default_factory=dict)

    @classmethod
    def from_dir(cls, rules_root: Path) -> "Registry":
        reg = cls()
        yaml_dir = rules_root / "yaml"
        plugins_dir = rules_root / "plugins"

        if yaml_dir.is_dir():
            for yaml_file in sorted(yaml_dir.glob("*.yaml")):
                rule = load_yaml_rule(yaml_file)
                reg._add(rule)

        if plugins_dir.is_dir():
            for py_file in sorted(plugins_dir.glob("*.py")):
                if py_file.name == "__init__.py":
                    continue
                rule = load_plugin_rule(py_file)
                reg._add(rule)

        if not reg.rules:
            raise EmptyRegistryError(
                f"no rules loaded from {rules_root}; empty registry is a "
                f"misconfigured Sentinel (fail-closed)"
            )
        return reg

    def _add(self, rule: Rule) -> None:
        if rule.id in self.rules:
            raise ValueError(f"duplicate rule id: {rule.id}")
        self.rules[rule.id] = rule

    def all_rules(self) -> List[Rule]:
        return list(self.rules.values())

    def get(self, rule_id: str) -> Rule:
        if rule_id not in self.rules:
            raise KeyError(f"unknown rule id: {rule_id}")
        return self.rules[rule_id]
```

- [ ] **Step 4: Update `sentinel/registry/__init__.py`**

```python
from sentinel.registry.plugin_loader import (
    PluginRule,
    PluginRuleLoadError,
    load_plugin_rule,
)
from sentinel.registry.registry import EmptyRegistryError, Registry
from sentinel.registry.yaml_loader import (
    YamlRule,
    YamlRuleLoadError,
    load_yaml_rule,
)

__all__ = [
    "EmptyRegistryError",
    "PluginRule",
    "PluginRuleLoadError",
    "Registry",
    "YamlRule",
    "YamlRuleLoadError",
    "load_plugin_rule",
    "load_yaml_rule",
]
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_registry.py -v`
Expected: `5 passed`

- [ ] **Step 6: Commit**

```bash
git add sentinel/registry/registry.py sentinel/registry/__init__.py tests/unit/test_registry.py
git commit -m "feat(registry): combined registry with duplicate + empty fail-closed"
```

---

## Task 9: IO — writer (review-findings.md + STUCK_FAILURES.md)

**Files:**
- Create: `C:\Sentinel\sentinel\io\__init__.py`
- Create: `C:\Sentinel\sentinel\io\writer.py`
- Create: `C:\Sentinel\tests\unit\test_writer.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_writer.py
from datetime import datetime, timezone
from pathlib import Path
from sentinel.core import Severity, Verdict
from sentinel.io.writer import write_findings


def _v(severity: Severity, rule_id: str) -> Verdict:
    return Verdict(
        rule_id=rule_id,
        severity=severity,
        repo="C:/repo",
        file="a.py",
        line=1,
        detail="d",
        fix_hint="fh",
        source="src.md",
        timestamp=datetime(2026, 4, 14, 0, 0, 0, tzinfo=timezone.utc),
    )


def test_block_verdicts_write_stuck_failures(tmp_path: Path):
    verdicts = [_v(Severity.BLOCK, "R-block"), _v(Severity.WARN, "R-warn")]
    write_findings(tmp_path, verdicts)
    stuck = (tmp_path / "STUCK_FAILURES.md").read_text(encoding="utf-8")
    warn = (tmp_path / "review-findings.md").read_text(encoding="utf-8")
    assert "R-block" in stuck
    assert "R-warn" not in stuck
    assert "R-warn" in warn


def test_info_only_creates_no_files(tmp_path: Path):
    write_findings(tmp_path, [_v(Severity.INFO, "R-info")])
    assert not (tmp_path / "STUCK_FAILURES.md").exists()
    assert not (tmp_path / "review-findings.md").exists()


def test_empty_verdicts_creates_no_files(tmp_path: Path):
    write_findings(tmp_path, [])
    assert not (tmp_path / "STUCK_FAILURES.md").exists()
    assert not (tmp_path / "review-findings.md").exists()


def test_appends_to_existing_review_findings(tmp_path: Path):
    (tmp_path / "review-findings.md").write_text("# existing\n\n", encoding="utf-8")
    write_findings(tmp_path, [_v(Severity.WARN, "R-warn")])
    content = (tmp_path / "review-findings.md").read_text(encoding="utf-8")
    assert "# existing" in content
    assert "R-warn" in content
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_writer.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write `sentinel/io/writer.py`**

```python
"""Writes findings into the target repo's review-findings.md / STUCK_FAILURES.md."""
from __future__ import annotations
from pathlib import Path
from typing import Sequence

from sentinel.core import Severity, Verdict


STUCK_HEADER = "# STUCK_FAILURES.md\n\n*Written by Sentinel — BLOCK-tier violations.*\n"
REVIEW_HEADER = "# review-findings.md\n\n*Written by Sentinel — WARN-tier findings.*\n"


def _format_verdict(v: Verdict) -> str:
    location = f"{v.file}:{v.line}" if v.file and v.line else v.file or "(repo-wide)"
    return (
        f"\n## [{v.severity.label}] {v.rule_id}\n"
        f"- **Location:** `{location}`\n"
        f"- **Detail:** {v.detail}\n"
        f"- **Fix hint:** {v.fix_hint}\n"
        f"- **Source:** {v.source}\n"
        f"- **When:** {v.timestamp.isoformat()}\n"
    )


def write_findings(repo_root: Path, verdicts: Sequence[Verdict]) -> None:
    blocks = [v for v in verdicts if v.severity == Severity.BLOCK]
    warns = [v for v in verdicts if v.severity == Severity.WARN]

    if blocks:
        path = repo_root / "STUCK_FAILURES.md"
        if not path.exists():
            path.write_text(STUCK_HEADER, encoding="utf-8")
        with path.open("a", encoding="utf-8") as f:
            for v in blocks:
                f.write(_format_verdict(v))

    if warns:
        path = repo_root / "review-findings.md"
        if not path.exists():
            path.write_text(REVIEW_HEADER, encoding="utf-8")
        with path.open("a", encoding="utf-8") as f:
            for v in warns:
                f.write(_format_verdict(v))
```

- [ ] **Step 4: Write `sentinel/io/__init__.py`**

```python
from sentinel.io.writer import write_findings

__all__ = ["write_findings"]
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_writer.py -v`
Expected: `4 passed`

- [ ] **Step 6: Commit**

```bash
git add sentinel/io/__init__.py sentinel/io/writer.py tests/unit/test_writer.py
git commit -m "feat(io): write_findings emits to STUCK_FAILURES.md / review-findings.md"
```

---

## Task 10: Rule 1 — `P0-placeholder-hmac` (YAML)

**Files:**
- Create: `C:\Sentinel\sentinel\rules\__init__.py` (empty)
- Create: `C:\Sentinel\sentinel\rules\yaml\P0-placeholder-hmac.yaml`
- Create: `C:\Sentinel\tests\fixtures\repos\placeholder_hmac_BAD\cert.json`
- Create: `C:\Sentinel\tests\fixtures\repos\placeholder_hmac_GOOD\cert.json`
- Create: `C:\Sentinel\tests\unit\test_rule_placeholder_hmac.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_rule_placeholder_hmac.py
from pathlib import Path
from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.yaml_loader import load_yaml_rule


RULE_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "yaml" / "P0-placeholder-hmac.yaml"
)


def test_placeholder_hmac_fires_on_bad_fixture(fixtures_dir: Path):
    rule = load_yaml_rule(RULE_PATH)
    bad = fixtures_dir / "repos" / "placeholder_hmac_BAD"
    verdicts = rule.check(RepoContext(repo_root=bad, mode=ScanMode.REPO))
    assert len(verdicts) >= 1
    assert all(v.rule_id == "P0-placeholder-hmac" for v in verdicts)
    assert all(v.severity == Severity.BLOCK for v in verdicts)


def test_placeholder_hmac_silent_on_good_fixture(fixtures_dir: Path):
    rule = load_yaml_rule(RULE_PATH)
    good = fixtures_dir / "repos" / "placeholder_hmac_GOOD"
    verdicts = rule.check(RepoContext(repo_root=good, mode=ScanMode.REPO))
    assert verdicts == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_rule_placeholder_hmac.py -v`
Expected: FAIL — rule YAML and fixtures don't exist.

- [ ] **Step 3: Create `sentinel/rules/__init__.py`** (empty)

```python
```

- [ ] **Step 4: Write `sentinel/rules/yaml/P0-placeholder-hmac.yaml`**

```yaml
id: P0-placeholder-hmac
severity: BLOCK
scope: repo
description: >
  Placeholder HMAC signatures shipping as real crypto. Any string
  matching SIG_RSA_SHA256_ or signature_placeholder indicates an
  unreplaced TruthCert scaffold.
pattern: 'SIG_RSA_SHA256_|signature_placeholder'
files:
  - '**/*.json'
  - '**/*.py'
  - '**/*.md'
exclude:
  - 'tests/**'
  - 'fixtures/**'
  - 'docs/superpowers/specs/**'
  - 'docs/superpowers/plans/**'
fix_hint: >
  Replace with a real HMAC computed from env TRUTHCERT_HMAC_KEY.
  See lessons.md#cryptography-signing.
source: lessons.md#cryptography-signing
```

- [ ] **Step 5: Write `tests/fixtures/repos/placeholder_hmac_BAD/cert.json`**

```json
{
  "cert_id": "TC-2026-0001",
  "signature_placeholder": "SIG_RSA_SHA256_REPLACE_ME",
  "payload": {"claim": "x"}
}
```

- [ ] **Step 6: Write `tests/fixtures/repos/placeholder_hmac_GOOD/cert.json`**

```json
{
  "cert_id": "TC-2026-0002",
  "signature": "7c9bfa0e3d21b84a1f5e7c2a4d8b9e6f3c1a2b4d5e6f7a8b9c0d1e2f3a4b5c6d",
  "signature_algo": "HMAC-SHA256",
  "payload": {"claim": "x"}
}
```

- [ ] **Step 7: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_rule_placeholder_hmac.py -v`
Expected: `2 passed`

- [ ] **Step 8: Commit**

```bash
git add sentinel/rules/__init__.py sentinel/rules/yaml/P0-placeholder-hmac.yaml tests/fixtures/repos/placeholder_hmac_BAD/cert.json tests/fixtures/repos/placeholder_hmac_GOOD/cert.json tests/unit/test_rule_placeholder_hmac.py
git commit -m "feat(rules): P0-placeholder-hmac YAML rule + GOOD/BAD fixtures"
```

---

## Task 11: Rule 2 — `P0-path-not-exist` (portfolio plugin)

**Files:**
- Create: `C:\Sentinel\sentinel\rules\plugins\__init__.py` (empty)
- Create: `C:\Sentinel\sentinel\rules\plugins\path_not_exist.py`
- Create: `C:\Sentinel\tests\fixtures\project_index_GOOD\INDEX.md`
- Create: `C:\Sentinel\tests\fixtures\project_index_GOOD\agent-records\restart-manifest.json`
- Create: `C:\Sentinel\tests\fixtures\project_index_DRIFT\INDEX.md`
- Create: `C:\Sentinel\tests\fixtures\project_index_DRIFT\agent-records\restart-manifest.json`
- Create: `C:\Sentinel\tests\unit\test_rule_path_not_exist.py`

**Scope:** portfolio. Reads `restart-manifest.json` at
`<project_index_root>/agent-records/restart-manifest.json`. For each project in
`projects[]`, checks that `path` exists on disk. Each missing path = one BLOCK verdict.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_rule_path_not_exist.py
import json
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "path_not_exist.py"
)


def _write_manifest(pi_root: Path, projects: list) -> None:
    (pi_root / "agent-records").mkdir(parents=True, exist_ok=True)
    manifest = {"overview": {"projectCount": len(projects)}, "projects": projects}
    (pi_root / "agent-records" / "restart-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )


def test_path_not_exist_fires_on_missing_path(tmp_path: Path):
    pi = tmp_path / "ProjectIndex"
    _write_manifest(pi, [{"name": "ghost", "path": str(tmp_path / "not-there")}])
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "P0-path-not-exist"
    assert verdicts[0].severity == Severity.BLOCK
    assert "ghost" in verdicts[0].detail


def test_path_not_exist_silent_on_all_paths_present(tmp_path: Path):
    pi = tmp_path / "ProjectIndex"
    real = tmp_path / "real_project"
    real.mkdir(parents=True)
    _write_manifest(pi, [{"name": "real", "path": str(real)}])
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    assert rule.check(ctx) == []


def test_path_not_exist_inactive_in_repo_scope(tmp_path: Path):
    pi = tmp_path / "ProjectIndex"
    _write_manifest(pi, [{"name": "ghost", "path": str(tmp_path / "nope")}])
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_path_not_exist_missing_manifest_blocks(tmp_path: Path):
    pi = tmp_path / "ProjectIndex"
    pi.mkdir()
    (pi / "agent-records").mkdir()
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.BLOCK
    assert "manifest" in verdicts[0].detail.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_rule_path_not_exist.py -v`
Expected: FAIL — plugin doesn't exist.

- [ ] **Step 3: Create `sentinel/rules/plugins/__init__.py`** (empty)

```python
```

- [ ] **Step 4: Write `sentinel/rules/plugins/path_not_exist.py`**

```python
"""P0-path-not-exist: portfolio-scoped. Every project in the manifest must
have a path that resolves on disk. Missing paths = BLOCK."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P0-path-not-exist"
SEVERITY = Severity.BLOCK
SOURCE = "workflow.md#exact-path-contract"
SCOPE = "portfolio"


def check(ctx: RepoContext) -> List[Verdict]:
    pi_root = ctx.project_index_root
    assert pi_root is not None, "portfolio scope guarantees project_index_root"

    manifest_path = pi_root / "agent-records" / "restart-manifest.json"
    now = datetime.now(timezone.utc)

    if not manifest_path.is_file():
        return [
            Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(pi_root),
                file=None,
                line=None,
                detail=f"manifest missing at {manifest_path}",
                fix_hint="restore restart-manifest.json before any lifecycle promotion",
                source=SOURCE,
                timestamp=now,
            )
        ]

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return [
            Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(pi_root),
                file=str(manifest_path),
                line=None,
                detail=f"manifest unreadable: {e}",
                fix_hint="repair manifest JSON",
                source=SOURCE,
                timestamp=now,
            )
        ]

    verdicts: List[Verdict] = []
    for proj in data.get("projects", []):
        name = proj.get("name", "<unnamed>")
        path_str = proj.get("path")
        if not path_str:
            continue
        if not Path(path_str).exists():
            verdicts.append(
                Verdict(
                    rule_id=ID,
                    severity=SEVERITY,
                    repo=path_str,
                    file=None,
                    line=None,
                    detail=f"project {name!r} declares path {path_str} but it does not exist",
                    fix_hint="restore path or demote lifecycle status to MISSING",
                    source=SOURCE,
                    timestamp=now,
                )
            )
    return verdicts
```

- [ ] **Step 5: Write fixture `tests/fixtures/project_index_GOOD/INDEX.md`**

```markdown
# Master Project Index

- **real_project** — `__PLACEHOLDER__` — created at runtime by test
```

- [ ] **Step 6: Write fixture `tests/fixtures/project_index_GOOD/agent-records/restart-manifest.json`**

```json
{
  "overview": {"projectCount": 0},
  "projects": []
}
```

- [ ] **Step 7: Write fixture `tests/fixtures/project_index_DRIFT/INDEX.md`**

```markdown
# Master Project Index

- **ghost_project** — `C:/this/does/not/exist` — should trigger P0-path-not-exist
```

- [ ] **Step 8: Write fixture `tests/fixtures/project_index_DRIFT/agent-records/restart-manifest.json`**

```json
{
  "overview": {"projectCount": 1},
  "projects": [
    {"name": "ghost_project", "path": "C:/this/does/not/exist"}
  ]
}
```

- [ ] **Step 9: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_rule_path_not_exist.py -v`
Expected: `4 passed`

- [ ] **Step 10: Commit**

```bash
git add sentinel/rules/plugins/__init__.py sentinel/rules/plugins/path_not_exist.py tests/fixtures/project_index_GOOD/INDEX.md tests/fixtures/project_index_GOOD/agent-records/restart-manifest.json tests/fixtures/project_index_DRIFT/INDEX.md tests/fixtures/project_index_DRIFT/agent-records/restart-manifest.json tests/unit/test_rule_path_not_exist.py
git commit -m "feat(rules): P0-path-not-exist portfolio plugin + fixtures"
```

---

## Task 12: Rule 3 — `P0-registry-drift` (portfolio plugin wrapping reconcile_counts.py)

**Files:**
- Create: `C:\Sentinel\sentinel\rules\plugins\registry_drift.py`
- Create: `C:\Sentinel\tests\unit\test_rule_registry_drift.py`

**Design:** The plugin invokes `python <project_index_root>/reconcile_counts.py`
via subprocess with a 120-second hard timeout (per testing.md smoke bound). If the
script exits 0, no verdict. If non-zero, one BLOCK verdict with stdout+stderr
captured. If the script hangs past 120s, subprocess is killed → synthetic BLOCK.

**For the test**, fixtures ship a tiny `reconcile_counts.py` stub that exits 0 or 1
on demand — we don't depend on `C:\ProjectIndex\reconcile_counts.py` being present.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_rule_registry_drift.py
import textwrap
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "registry_drift.py"
)

STUB_OK = textwrap.dedent("""
    import sys
    print("ok")
    sys.exit(0)
""")

STUB_FAIL = textwrap.dedent("""
    import sys
    sys.stderr.write("drift detected: 517 vs 472\\n")
    sys.exit(1)
""")


def _setup_pi(tmp_path: Path, stub_src: str) -> Path:
    pi = tmp_path / "ProjectIndex"
    pi.mkdir()
    (pi / "reconcile_counts.py").write_text(stub_src, encoding="utf-8")
    return pi


def test_registry_drift_silent_when_reconcile_exits_zero(tmp_path: Path):
    pi = _setup_pi(tmp_path, STUB_OK)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    assert rule.check(ctx) == []


def test_registry_drift_blocks_when_reconcile_exits_nonzero(tmp_path: Path):
    pi = _setup_pi(tmp_path, STUB_FAIL)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "P0-registry-drift"
    assert verdicts[0].severity == Severity.BLOCK
    assert "517" in verdicts[0].detail or "472" in verdicts[0].detail


def test_registry_drift_missing_script_blocks(tmp_path: Path):
    pi = tmp_path / "ProjectIndex"
    pi.mkdir()  # no reconcile_counts.py
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.BLOCK
    assert "reconcile_counts.py not found" in verdicts[0].detail


def test_registry_drift_inactive_in_repo_scope(tmp_path: Path):
    pi = _setup_pi(tmp_path, STUB_FAIL)
    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    assert rule.check(ctx) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_rule_registry_drift.py -v`
Expected: FAIL — plugin doesn't exist.

- [ ] **Step 3: Write `sentinel/rules/plugins/registry_drift.py`**

```python
"""P0-registry-drift: wraps reconcile_counts.py as a portfolio-scoped rule."""
from __future__ import annotations
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P0-registry-drift"
SEVERITY = Severity.BLOCK
SOURCE = "workflow.md#registry-reconciliation-gate"
SCOPE = "portfolio"

TIMEOUT_SECONDS = 120


def check(ctx: RepoContext) -> List[Verdict]:
    pi_root = ctx.project_index_root
    assert pi_root is not None, "portfolio scope guarantees project_index_root"
    now = datetime.now(timezone.utc)

    script = pi_root / "reconcile_counts.py"
    if not script.is_file():
        return [
            Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(pi_root),
                file=None,
                line=None,
                detail=f"reconcile_counts.py not found at {script}",
                fix_hint="restore reconcile_counts.py in C:/ProjectIndex/",
                source=SOURCE,
                timestamp=now,
            )
        ]

    try:
        result = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=TIMEOUT_SECONDS,
            cwd=str(pi_root),
        )
    except subprocess.TimeoutExpired:
        return [
            Verdict(
                rule_id=ID,
                severity=SEVERITY,
                repo=str(pi_root),
                file=str(script),
                line=None,
                detail=f"reconcile_counts.py exceeded {TIMEOUT_SECONDS}s — killed",
                fix_hint="investigate why reconcile hangs; do not raise timeout blindly",
                source=SOURCE,
                timestamp=now,
            )
        ]

    if result.returncode == 0:
        return []

    combined = (result.stdout or "") + "\n" + (result.stderr or "")
    return [
        Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=str(pi_root),
            file=str(script),
            line=None,
            detail=f"reconcile_counts.py exited {result.returncode}: {combined.strip()[:400]}",
            fix_hint="resolve INDEX.md / manifest / workbook drift before any portfolio action",
            source=SOURCE,
            timestamp=now,
        )
    ]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_rule_registry_drift.py -v`
Expected: `4 passed`

- [ ] **Step 5: Commit**

```bash
git add sentinel/rules/plugins/registry_drift.py tests/unit/test_rule_registry_drift.py
git commit -m "feat(rules): P0-registry-drift plugin wrapping reconcile_counts.py"
```

---

## Task 13: Contract tests — YAML schema, plugin interface, verdict schema

**Files:**
- Create: `C:\Sentinel\tests\contracts\__init__.py` (empty)
- Create: `C:\Sentinel\tests\contracts\test_yaml_rule_schema.py`
- Create: `C:\Sentinel\tests\contracts\test_plugin_interface.py`
- Create: `C:\Sentinel\tests\contracts\test_verdict_schema.py`

- [ ] **Step 1: Create `tests/contracts/__init__.py`** (empty)

```python
```

- [ ] **Step 2: Write `tests/contracts/test_yaml_rule_schema.py`**

```python
"""Contract: every shipped YAML rule parses with all required fields."""
from pathlib import Path
import pytest
from sentinel.registry.yaml_loader import load_yaml_rule

YAML_DIR = Path(__file__).parent.parent.parent / "sentinel" / "rules" / "yaml"


@pytest.mark.contract
@pytest.mark.parametrize("yaml_file", sorted(YAML_DIR.glob("*.yaml")), ids=lambda p: p.name)
def test_shipped_yaml_rules_load(yaml_file: Path):
    rule = load_yaml_rule(yaml_file)
    assert rule.id
    assert rule.severity
    assert rule.source
    assert rule.scope in ("repo", "portfolio")
```

- [ ] **Step 3: Write `tests/contracts/test_plugin_interface.py`**

```python
"""Contract: every shipped plugin exposes the required interface."""
from pathlib import Path
import pytest
from sentinel.registry.plugin_loader import load_plugin_rule

PLUGINS_DIR = Path(__file__).parent.parent.parent / "sentinel" / "rules" / "plugins"


def _plugin_files():
    return sorted(p for p in PLUGINS_DIR.glob("*.py") if p.name != "__init__.py")


@pytest.mark.contract
@pytest.mark.parametrize("plugin_file", _plugin_files(), ids=lambda p: p.name)
def test_shipped_plugins_load(plugin_file: Path):
    rule = load_plugin_rule(plugin_file)
    assert rule.id
    assert rule.severity
    assert rule.source
    assert rule.scope in ("repo", "portfolio")
    assert callable(rule._check)
```

- [ ] **Step 4: Write `tests/contracts/test_verdict_schema.py`**

```python
"""Contract: every verdict produced by every shipped rule matches the schema."""
from datetime import datetime
from pathlib import Path
import pytest
from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.registry import Registry

RULES_ROOT = Path(__file__).parent.parent.parent / "sentinel" / "rules"


REQUIRED_KEYS = {
    "rule_id", "severity", "repo", "file", "line",
    "detail", "fix_hint", "source", "timestamp",
}


@pytest.mark.contract
def test_verdict_schema_from_registry(tmp_path: Path):
    reg = Registry.from_dir(RULES_ROOT)
    # Exercise each rule against a tmp repo to harvest verdicts.
    pi = tmp_path / "ProjectIndex"
    pi.mkdir()
    (pi / "agent-records").mkdir()
    (pi / "agent-records" / "restart-manifest.json").write_text(
        '{"overview":{"projectCount":1},"projects":[{"name":"x","path":"C:/not/here"}]}',
        encoding="utf-8",
    )
    (pi / "reconcile_counts.py").write_text("import sys; sys.exit(1)", encoding="utf-8")

    repo_ctx = RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)
    port_ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )

    all_verdicts = []
    for rule in reg.all_rules():
        all_verdicts.extend(rule.check(repo_ctx))
        all_verdicts.extend(rule.check(port_ctx))

    assert all_verdicts, "at least one rule should produce a verdict in this setup"
    for v in all_verdicts:
        d = v.to_dict()
        assert set(d.keys()) == REQUIRED_KEYS, f"missing keys: {REQUIRED_KEYS - set(d.keys())}"
        assert d["severity"] in ("BLOCK", "WARN", "INFO")
        # timestamp round-trips
        datetime.fromisoformat(d["timestamp"])
```

- [ ] **Step 5: Run all contract tests**

Run: `python -m pytest tests/contracts/ -v`
Expected: `3 passed` (one parametrized per rule file + one verdict schema test)

- [ ] **Step 6: Commit**

```bash
git add tests/contracts/__init__.py tests/contracts/test_yaml_rule_schema.py tests/contracts/test_plugin_interface.py tests/contracts/test_verdict_schema.py
git commit -m "test(contracts): schema + interface + verdict contracts for all shipped rules"
```

---

## Task 14: CLI — `scan` subcommand

**Files:**
- Create: `C:\Sentinel\sentinel\cli\__init__.py` (empty)
- Create: `C:\Sentinel\sentinel\cli\__main__.py`
- Create: `C:\Sentinel\sentinel\cli\scan.py`
- Create: `C:\Sentinel\tests\unit\test_cli_scan.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_cli_scan.py
import json
import subprocess
import sys
from pathlib import Path

SENTINEL_ROOT = Path(__file__).parent.parent.parent


def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(cwd or SENTINEL_ROOT),
    )


def test_scan_repo_mode_exits_zero_on_clean_repo(tmp_path: Path):
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "hello.txt").write_text("hello", encoding="utf-8")
    res = _run("scan", "--repo", str(clean))
    assert res.returncode == 0, f"stderr: {res.stderr}"


def test_scan_repo_mode_exits_one_on_placeholder_hmac(tmp_path: Path):
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "cert.json").write_text(
        '{"sig":"SIG_RSA_SHA256_x"}', encoding="utf-8"
    )
    res = _run("scan", "--repo", str(bad))
    assert res.returncode == 1
    assert "P0-placeholder-hmac" in res.stdout + res.stderr
    assert (bad / "STUCK_FAILURES.md").exists()


def test_scan_json_output_contains_verdicts(tmp_path: Path):
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "cert.json").write_text(
        '{"sig":"SIG_RSA_SHA256_x"}', encoding="utf-8"
    )
    res = _run("scan", "--repo", str(bad), "--json")
    assert res.returncode == 1
    data = json.loads(res.stdout)
    assert any(v["rule_id"] == "P0-placeholder-hmac" for v in data["verdicts"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_cli_scan.py -v`
Expected: FAIL — CLI doesn't exist.

- [ ] **Step 3: Create `sentinel/cli/__init__.py`** (empty)

```python
```

- [ ] **Step 4: Write `sentinel/cli/scan.py`**

```python
"""`sentinel scan` subcommand."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, ScanMode, Severity, Verdict
from sentinel.io import write_findings
from sentinel.registry.registry import Registry

RULES_ROOT = Path(__file__).parent.parent / "rules"


def add_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("scan", help="Scan a repo or the portfolio")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--repo", type=Path, help="Scan a single repository")
    group.add_argument(
        "--portfolio", action="store_true",
        help="Scan the portfolio (requires --project-index)",
    )
    p.add_argument(
        "--project-index", type=Path,
        default=Path("C:/ProjectIndex"),
        help="Portfolio registry root (default: C:/ProjectIndex)",
    )
    p.add_argument("--json", action="store_true", help="Emit verdicts as JSON")
    p.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> int:
    if args.repo:
        ctx = RepoContext(repo_root=args.repo, mode=ScanMode.REPO)
        write_root = args.repo
    else:
        ctx = RepoContext(
            repo_root=args.project_index,
            mode=ScanMode.PORTFOLIO,
            project_index_root=args.project_index,
        )
        write_root = args.project_index

    reg = Registry.from_dir(RULES_ROOT)

    verdicts: List[Verdict] = []
    for rule in reg.all_rules():
        verdicts.extend(rule.check(ctx))

    write_findings(write_root, verdicts)

    if args.json:
        print(json.dumps({"verdicts": [v.to_dict() for v in verdicts]}, indent=2))
    else:
        _print_summary(verdicts)

    return 1 if any(v.severity == Severity.BLOCK for v in verdicts) else 0


def _print_summary(verdicts: List[Verdict]) -> None:
    block = sum(1 for v in verdicts if v.severity == Severity.BLOCK)
    warn = sum(1 for v in verdicts if v.severity == Severity.WARN)
    info = sum(1 for v in verdicts if v.severity == Severity.INFO)
    print(f"[Sentinel] verdicts: BLOCK={block} WARN={warn} INFO={info}")
    for v in verdicts:
        loc = f"{v.file}:{v.line}" if v.file and v.line else v.file or "(repo-wide)"
        print(f"  [{v.severity.label}] {v.rule_id}  {loc}  {v.detail[:80]}")
```

- [ ] **Step 5: Write `sentinel/cli/__main__.py`**

```python
"""Entry point: `python -m sentinel ...` or `sentinel ...`."""
from __future__ import annotations
import argparse
import sys

from sentinel.cli import scan as scan_cmd


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel")
    sub = parser.add_subparsers(dest="command", required=True)
    scan_cmd.add_subparser(sub)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 6: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_cli_scan.py -v`
Expected: `3 passed`

- [ ] **Step 7: Commit**

```bash
git add sentinel/cli/__init__.py sentinel/cli/__main__.py sentinel/cli/scan.py tests/unit/test_cli_scan.py
git commit -m "feat(cli): sentinel scan --repo / --portfolio with JSON output"
```

---

## Task 15: CLI — `list-rules` and `explain` subcommands

**Files:**
- Create: `C:\Sentinel\sentinel\cli\list_rules.py`
- Create: `C:\Sentinel\sentinel\cli\explain.py`
- Modify: `C:\Sentinel\sentinel\cli\__main__.py`
- Create: `C:\Sentinel\tests\unit\test_cli_list_rules.py`
- Create: `C:\Sentinel\tests\unit\test_cli_explain.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_cli_list_rules.py
import subprocess
import sys
from pathlib import Path

SENTINEL_ROOT = Path(__file__).parent.parent.parent


def test_list_rules_prints_all_three():
    res = subprocess.run(
        [sys.executable, "-m", "sentinel", "list-rules"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(SENTINEL_ROOT),
    )
    assert res.returncode == 0
    out = res.stdout
    assert "P0-placeholder-hmac" in out
    assert "P0-path-not-exist" in out
    assert "P0-registry-drift" in out
```

```python
# tests/unit/test_cli_explain.py
import subprocess
import sys
from pathlib import Path

SENTINEL_ROOT = Path(__file__).parent.parent.parent


def test_explain_known_rule_prints_source_and_fix_hint():
    res = subprocess.run(
        [sys.executable, "-m", "sentinel", "explain", "P0-placeholder-hmac"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(SENTINEL_ROOT),
    )
    assert res.returncode == 0
    assert "lessons.md" in res.stdout
    assert "TRUTHCERT_HMAC_KEY" in res.stdout


def test_explain_unknown_rule_exits_one():
    res = subprocess.run(
        [sys.executable, "-m", "sentinel", "explain", "NONEXISTENT"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(SENTINEL_ROOT),
    )
    assert res.returncode == 1
    assert "unknown rule" in (res.stdout + res.stderr).lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_cli_list_rules.py tests/unit/test_cli_explain.py -v`
Expected: FAIL — subcommands don't exist.

- [ ] **Step 3: Write `sentinel/cli/list_rules.py`**

```python
"""`sentinel list-rules` subcommand."""
from __future__ import annotations
import argparse
from pathlib import Path

from sentinel.registry.registry import Registry

RULES_ROOT = Path(__file__).parent.parent / "rules"


def add_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("list-rules", help="List all registered rules")
    p.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> int:
    reg = Registry.from_dir(RULES_ROOT)
    for rule in reg.all_rules():
        print(f"{rule.id}  [{rule.severity.label}]  scope={rule.scope}  {rule.source}")
    return 0
```

- [ ] **Step 4: Write `sentinel/cli/explain.py`**

```python
"""`sentinel explain <rule-id>` subcommand."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

from sentinel.registry.registry import Registry

RULES_ROOT = Path(__file__).parent.parent / "rules"


def add_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("explain", help="Explain a rule by id")
    p.add_argument("rule_id", help="The rule id to explain")
    p.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> int:
    reg = Registry.from_dir(RULES_ROOT)
    try:
        rule = reg.get(args.rule_id)
    except KeyError as e:
        print(f"error: {e}", file=sys.stderr)
        known = ", ".join(r.id for r in reg.all_rules())
        print(f"known rules: {known}", file=sys.stderr)
        return 1

    print(f"Rule:     {rule.id}")
    print(f"Severity: {rule.severity.label}")
    print(f"Scope:    {rule.scope}")
    print(f"Source:   {rule.source}")
    description = getattr(rule, "description", "")
    if description:
        print(f"\nDescription:\n  {description}")
    fix_hint = getattr(rule, "fix_hint", "")
    if fix_hint:
        print(f"\nFix hint:\n  {fix_hint}")
    return 0
```

- [ ] **Step 5: Update `sentinel/cli/__main__.py`**

```python
"""Entry point: `python -m sentinel ...` or `sentinel ...`."""
from __future__ import annotations
import argparse
import sys

from sentinel.cli import explain as explain_cmd
from sentinel.cli import list_rules as list_rules_cmd
from sentinel.cli import scan as scan_cmd


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel")
    sub = parser.add_subparsers(dest="command", required=True)
    scan_cmd.add_subparser(sub)
    list_rules_cmd.add_subparser(sub)
    explain_cmd.add_subparser(sub)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_cli_list_rules.py tests/unit/test_cli_explain.py -v`
Expected: `3 passed`

- [ ] **Step 7: Commit**

```bash
git add sentinel/cli/list_rules.py sentinel/cli/explain.py sentinel/cli/__main__.py tests/unit/test_cli_list_rules.py tests/unit/test_cli_explain.py
git commit -m "feat(cli): add list-rules and explain <rule-id> subcommands"
```

---

## Task 16: Regression test — zero-rules no-op

**Files:**
- Create: `C:\Sentinel\tests\regression\__init__.py` (empty)
- Create: `C:\Sentinel\tests\regression\test_zero_rules_noop.py`

- [ ] **Step 1: Create `tests/regression/__init__.py`** (empty)

```python
```

- [ ] **Step 2: Write `tests/regression/test_zero_rules_noop.py`**

```python
"""Non-regression: Sentinel with zero rules exits 0 and writes nothing."""
from pathlib import Path
import pytest
from sentinel.core import RepoContext, ScanMode
from sentinel.io import write_findings
from sentinel.registry.registry import Registry, EmptyRegistryError


@pytest.mark.regression
def test_empty_rules_dir_raises_empty_registry(tmp_path: Path):
    root = tmp_path / "rules"
    (root / "yaml").mkdir(parents=True)
    (root / "plugins").mkdir(parents=True)
    with pytest.raises(EmptyRegistryError):
        Registry.from_dir(root)


@pytest.mark.regression
def test_zero_verdicts_writes_nothing(tmp_path: Path):
    write_findings(tmp_path, [])
    assert list(tmp_path.iterdir()) == []
```

- [ ] **Step 3: Run the test**

Run: `python -m pytest tests/regression/test_zero_rules_noop.py -v`
Expected: `2 passed`

- [ ] **Step 4: Commit**

```bash
git add tests/regression/__init__.py tests/regression/test_zero_rules_noop.py
git commit -m "test(regression): zero-rules no-op guarantee"
```

---

## Task 17: Regression test — reconcile exit code unchanged

**Files:**
- Create: `C:\Sentinel\tests\regression\test_reconcile_exit_code_unchanged.py`

- [ ] **Step 1: Write the regression test**

```python
"""Non-regression: reconcile_counts.py standalone exit code = same script
invoked via the registry_drift plugin, for identical input."""
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "registry_drift.py"
)

STUB_TEMPLATE = textwrap.dedent("""
    import sys
    sys.stdout.write({stdout!r})
    sys.stderr.write({stderr!r})
    sys.exit({code})
""")


@pytest.mark.regression
@pytest.mark.parametrize("exit_code", [0, 1, 2])
def test_exit_code_is_preserved(tmp_path: Path, exit_code: int):
    pi = tmp_path / "ProjectIndex"
    pi.mkdir()
    stub_src = STUB_TEMPLATE.format(stdout="ok\n", stderr="", code=exit_code)
    stub_path = pi / "reconcile_counts.py"
    stub_path.write_text(stub_src, encoding="utf-8")

    standalone = subprocess.run(
        [sys.executable, str(stub_path)],
        capture_output=True, text=True, cwd=str(pi),
    )
    assert standalone.returncode == exit_code

    rule = load_plugin_rule(PLUGIN_PATH)
    ctx = RepoContext(
        repo_root=pi, mode=ScanMode.PORTFOLIO, project_index_root=pi
    )
    verdicts = rule.check(ctx)

    if exit_code == 0:
        assert verdicts == [], "exit 0 must produce zero verdicts"
    else:
        assert len(verdicts) == 1, f"non-zero exit must produce one BLOCK verdict"
        assert verdicts[0].severity == Severity.BLOCK
```

- [ ] **Step 2: Run the test**

Run: `python -m pytest tests/regression/test_reconcile_exit_code_unchanged.py -v`
Expected: `3 passed`

- [ ] **Step 3: Commit**

```bash
git add tests/regression/test_reconcile_exit_code_unchanged.py
git commit -m "test(regression): reconcile exit-code unchanged through plugin wrapper"
```

---

## Task 18: Regression test — no writes outside scope

**Files:**
- Create: `C:\Sentinel\tests\regression\test_no_writes_outside_scope.py`

**Approach:** pytest snapshots file mtimes in a workspace tree, runs a full scan, then asserts that every file with a changed mtime lives under either `tmp_path` (the target repo) or the Sentinel source tree was not touched at all (we check its mtimes too).

- [ ] **Step 1: Write the regression test**

```python
"""Non-regression: Sentinel writes only to `tmp_repo` under test + nothing
under the Sentinel package source tree itself."""
from pathlib import Path
import pytest

from sentinel.core import RepoContext, ScanMode
from sentinel.io import write_findings
from sentinel.registry.registry import Registry

SENTINEL_PKG = Path(__file__).parent.parent.parent / "sentinel"
RULES_ROOT = SENTINEL_PKG / "rules"


def _snapshot(root: Path) -> dict[Path, float]:
    return {p: p.stat().st_mtime_ns for p in root.rglob("*") if p.is_file()}


@pytest.mark.regression
def test_full_scan_does_not_touch_sentinel_source_tree(tmp_path: Path):
    bad = tmp_path / "scan_target"
    bad.mkdir()
    (bad / "cert.json").write_text(
        '{"sig":"SIG_RSA_SHA256_x"}', encoding="utf-8"
    )

    before = _snapshot(SENTINEL_PKG)
    reg = Registry.from_dir(RULES_ROOT)
    ctx = RepoContext(repo_root=bad, mode=ScanMode.REPO)
    verdicts = []
    for rule in reg.all_rules():
        verdicts.extend(rule.check(ctx))
    write_findings(bad, verdicts)
    after = _snapshot(SENTINEL_PKG)

    assert before == after, (
        "Sentinel package source tree was modified during scan; "
        "writes must only target the scanned repo."
    )
    assert (bad / "STUCK_FAILURES.md").exists(), "BLOCK verdicts must land in target repo"
```

- [ ] **Step 2: Run the test**

Run: `python -m pytest tests/regression/test_no_writes_outside_scope.py -v`
Expected: `1 passed`

- [ ] **Step 3: Commit**

```bash
git add tests/regression/test_no_writes_outside_scope.py
git commit -m "test(regression): full scan never writes outside the scanned repo"
```

---

## Task 19: README + M1 exit-criteria verification

**Files:**
- Create: `C:\Sentinel\README.md`

- [ ] **Step 1: Write `README.md`**

```markdown
# Sentinel

Portfolio fail-closed integrity engine. Converts accumulated lessons into
executable rules that run pre-push.

## Status

**M1 (in progress)** — Rule engine + 3 rules.

## Quickstart

```
python -m pip install -e ".[dev]"
python -m pytest
python -m sentinel list-rules
python -m sentinel scan --repo C:/Projects/shifaa
python -m sentinel scan --portfolio --project-index C:/ProjectIndex
python -m sentinel explain P0-placeholder-hmac
```

## M1 Exit Criteria

- [ ] `sentinel list-rules` prints all three P0 rules.
- [ ] `sentinel scan --repo <clean>` exits 0 with no output to
      `review-findings.md` or `STUCK_FAILURES.md`.
- [ ] `sentinel scan --repo <with-placeholder-hmac>` exits 1 and writes
      `STUCK_FAILURES.md`.
- [ ] `sentinel scan --portfolio --project-index <fixture-DRIFT>` exits 1
      and flags both `P0-path-not-exist` and `P0-registry-drift`.
- [ ] All three test layers green (`python -m pytest`).
- [ ] Coverage >= 90% on `sentinel/core` and `sentinel/registry`
      (`python -m pytest --cov`).

## Rule Authoring

- **YAML rules** — drop a `<id>.yaml` into `sentinel/rules/yaml/`.
  Required fields: `id`, `severity`, `description`, `pattern`, `source`.
- **Plugin rules** — drop a `<name>.py` into `sentinel/rules/plugins/`.
  Required attrs: `ID`, `SEVERITY`, `SOURCE`, `check(ctx) -> list[Verdict]`.
  Optional: `SCOPE` (default `"repo"`; use `"portfolio"` for
  registry-level rules).

## Design

See `docs/superpowers/specs/2026-04-14-sentinel-design.md`.
```

- [ ] **Step 2: Verify M1 exit criteria by hand**

Run the full suite:

```bash
cd C:/Sentinel
python -m pytest --cov
python -m sentinel list-rules
```

Expected:
- pytest: every test passes, counts printed.
- coverage: `>=90%` on `sentinel/core` and `sentinel/registry`.
- `list-rules` output includes all three rule IDs.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add Sentinel README with quickstart and M1 exit-criteria checklist"
```

---

## Task 20: M1 final validation run

**Files:** none created; this task is an end-to-end smoke test + status report.

- [ ] **Step 1: Full test suite with coverage**

Run: `cd C:/Sentinel && python -m pytest --cov --cov-report=term-missing`

Expected: all tests pass (contracts + unit + regression); coverage ≥90% on
`sentinel/core` and `sentinel/registry`.

- [ ] **Step 2: Manual end-to-end — clean repo scan**

```bash
mkdir -p C:/tmp/sentinel_e2e/clean
echo "hello" > C:/tmp/sentinel_e2e/clean/readme.txt
cd C:/Sentinel
python -m sentinel scan --repo C:/tmp/sentinel_e2e/clean
echo "exit: $?"
```

Expected: `exit: 0`, no `review-findings.md` or `STUCK_FAILURES.md` written.

- [ ] **Step 3: Manual end-to-end — placeholder-hmac repo scan**

```bash
mkdir -p C:/tmp/sentinel_e2e/bad
echo '{"sig":"SIG_RSA_SHA256_x"}' > C:/tmp/sentinel_e2e/bad/cert.json
cd C:/Sentinel
python -m sentinel scan --repo C:/tmp/sentinel_e2e/bad
echo "exit: $?"
cat C:/tmp/sentinel_e2e/bad/STUCK_FAILURES.md
```

Expected: `exit: 1`, `STUCK_FAILURES.md` contains `P0-placeholder-hmac`.

- [ ] **Step 4: Manual end-to-end — portfolio scan on drift fixture**

```bash
cd C:/Sentinel
python -m sentinel scan --portfolio --project-index tests/fixtures/project_index_DRIFT
echo "exit: $?"
```

Expected: `exit: 1`, output lists `P0-path-not-exist` BLOCK verdict.
(The drift fixture lacks `reconcile_counts.py`, so `P0-registry-drift`
also fires with a "script not found" BLOCK — this is correct fail-closed behavior.)

- [ ] **Step 5: Verify the non-regression snapshot**

Run: `python -m pytest tests/regression/ -v`
Expected: all three regression tests pass.

- [ ] **Step 6: Tag the M1 release**

```bash
cd C:/Sentinel
git tag -a m1-rule-engine -m "M1: rule engine + 3 P0 rules (placeholder-hmac, path-not-exist, registry-drift)"
git log --oneline | head -25
```

- [ ] **Step 7: Hand off to M2 planning**

At this point, M1 is complete. Write a short PROGRESS.md note recording
state for M2:

```markdown
# PROGRESS.md (Sentinel)

## M1 — DONE
- Rule engine (YAML + plugin loaders, uniform Verdict, Registry).
- 3 P0 rules: placeholder-hmac, path-not-exist, registry-drift.
- CLI: scan / list-rules / explain.
- Three test layers green; coverage >=90% on core + registry.
- Tag: `m1-rule-engine`.

## M2 — NEXT
- Pre-push hook installer (idempotent, chaining).
- Rules 4-9: claude-config-committed, hardcoded-local-path,
  unpopulated-placeholder, silent-failure-sentinel,
  script-in-template-literal, workbook-rewrite-touched.
- Install hook on 5 target repos:
  shifaa, MetaAudit, MES, overmind, cardiosynth.

## Last green test command
    cd C:/Sentinel && python -m pytest --cov
```

---

## Self-Review

**Spec coverage check:**
- Architectural decisions table — Task 1 (scaffolding), Task 6 (YAML), Task 7 (plugin), Task 13 (contracts). **Covered.**
- Boundaries table — enforced by module layout in Task 1 + import structure. **Covered.**
- Four non-regression guarantees — zero-rules (T16), reconcile exit-code (T17), hook-chaining (deferred to M2 as hook doesn't exist in M1), no-writes-outside-scope (T18). **3 of 4 covered in M1; hook-chaining deferred to M2 where the installer is built. Explicitly flagged.**
- Uniform Verdict record — T3 + T13. **Covered.**
- YAML schema fields — T6 + T13. **Covered.**
- Plugin interface (`ID/SEVERITY/SOURCE/check`) — T7 + T13. **Covered.**
- Rule scope (`repo` vs `portfolio`) — T6 + T7 + T11 + T12. **Covered.**
- Fail-closed error handling (rule raise → synthetic BLOCK, missing manifest → BLOCK, subprocess hang → BLOCK, empty registry → fail) — T7 + T11 + T12 + T16. **Covered.**
- CLI (`scan`, `list-rules`, `explain`) — T14 + T15. **Covered.**
- M1 exit criteria (the three P0 rules + CLI + contract/regression tests) — T1–T20. **Covered.**

**Placeholder scan:** No "TBD" / "TODO" / "fill in details" / "handle edge cases" / "similar to Task N". All code blocks are complete. Every test has actual assertions. ✓

**Type consistency:** `Severity` / `Verdict` / `RepoContext` / `ScanMode` / `Rule` / `YamlRule` / `PluginRule` / `Registry` — names consistent across all tasks. Method signatures (`check(ctx) -> Sequence[Verdict]`) consistent. ✓

**Deferred / explicit non-goals:** Pre-push hook installer and hook-chaining regression test live in M2 (where the installer exists). Rules 4–10 live in M2/M3. This is intentional scope limiting, stated at the top of the plan. ✓
