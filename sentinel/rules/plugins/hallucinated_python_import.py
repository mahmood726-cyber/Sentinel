# sentinel:skip-file — docstring example contains the bad pattern.
"""P1-hallucinated-python-import: WARN on `from <pkg> import <name>` where
<pkg> is an installed library and <name> is not an attribute of it —
the canonical LLM-hallucinated-API shape.

Approach (paraphrased from Hassan et al., "Detecting and Correcting
Hallucinations in LLM-Generated Code via Deterministic AST Analysis",
arXiv 2601.19106): walk each .py file's AST, find every ImportFrom
node whose module resolves on disk, then verify each name in the
import list actually exists as an attribute. Suggest closest-match
via difflib for the diagnostic detail. Reported 100% precision /
0.934 F1 on Python.

Scope is restricted to a small allowlist of packages that are (a)
commonly LLM-hallucinated against and (b) safe to import for
reflection — they don't make network calls or register global state
at import time. Catches:

    from pandas import read_exel           # → read_excel
    from numpy import linalg_norm          # → numpy.linalg.norm (not a top-level)
    from scipy import optimze              # → optimize
    from sklearn import preprcessing       # → preprocessing
    from requests import get_url           # not a thing — use requests.get

Skips:
    - relative imports (`from . import X`)
    - imports inside `try: ... except (ImportError, ModuleNotFoundError):`
      blocks (intentional optional imports)
    - wildcard imports (`from X import *`)
    - aliased imports where checking attribute existence becomes brittle
    - any package not in the allowlist (so a missing 3rd-party in the
      scan env doesn't false-positive)

The allowlist is deliberately small — expanding it requires
import-time-safety review per package.
"""
from __future__ import annotations

import ast
import difflib
import importlib
import importlib.util
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import iter_repo_files
from sentinel.io.population import Population
from sentinel.io.skip_marker import has_skip_marker, line_is_suppressed


ID = "P1-hallucinated-python-import"
SEVERITY = Severity.WARN
SOURCE = ("arXiv 2601.19106 (Hassan et al., 'Detecting and Correcting "
          "Hallucinations in LLM-Generated Code via Deterministic AST "
          "Analysis') — adapted to a focused allowlist for pre-push use")
SCOPE = "repo"

# Population: PRESENT -- tracked AND untracked-not-ignored. This is a
# CORRECTNESS rule: the defect it finds runs when someone runs the file,
# whether or not git is tracking it. Migrated 2026-08-30; counts from
# before that date were taken over the tracked set only and are NOT
# comparable with counts after it.
POPULATION = Population.PRESENT

MAX_FILE_BYTES = 2_000_000
PY_EXCLUDE_DIRS = (".venv", "venv", "__pycache__", "build", "dist",
                   ".tox", ".pytest_cache", "node_modules", "site-packages")

# Packages where:
#   1. LLM agents commonly hallucinate APIs against them
#   2. Importing is safe (no network, no side effects, no global
#      registrations that affect host process state)
#   3. The package is widely-enough installed that "not installed in
#      scan env" is rare in practice
ALLOWLIST_PACKAGES = frozenset({
    # Original 23-package set (data-science, web, testing, stdlib basics)
    "pandas", "numpy", "scipy", "sklearn", "statsmodels", "matplotlib",
    "seaborn", "requests", "httpx", "pytest", "hypothesis", "json",
    "os", "sys", "pathlib", "collections", "itertools", "functools",
    "re", "math", "random", "datetime", "time",
    # 2026-05 expansion — all safe to import for reflection (no network,
    # no side effects). Stdlib first:
    "argparse",      # CLI parsing — LLMs hallucinate add_arg vs add_argument
    "csv",           # CSV reader/writer — common reader= keyword hallucinations
    "dataclasses",   # field vs Field, MISSING vs missing
    "logging",       # getLogger vs get_logger common hallucination
    "subprocess",    # run vs call vs Popen confusion
    "tomllib",       # Py 3.11+ stdlib TOML reader (read-only)
    "typing",        # List vs list, Tuple vs tuple, Annotated patterns
    "unittest",      # assertEquals (Java-style) vs assertEqual hallucination
    # Popular 3rd-party — installed in most data/AI workspaces:
    "polars",        # modern dataframe lib; LLMs port pandas patterns wrongly
    "pydantic",      # v1 vs v2 API rename (BaseModel.dict vs .model_dump)
    "openai",        # SDK v0 vs v1 churn; LLMs frequently mix the two
    "anthropic",     # Same churn pattern; small canonical API
})

# Lazy-loaded module cache: { package_name: module_or_None }
_module_cache: dict[str, object | None] = {}


def _safe_import(package: str):
    """Import `package` once, cache the result (or None on failure).
    Bail-safe on any exception — never crashes the scan."""
    if package in _module_cache:
        return _module_cache[package]
    try:
        spec = importlib.util.find_spec(package)
        if spec is None:
            _module_cache[package] = None
            return None
        _module_cache[package] = importlib.import_module(package)
    except Exception:
        _module_cache[package] = None
    return _module_cache[package]


def _is_optional_import_context(node: ast.AST, tree: ast.AST) -> bool:
    """True if `node` is inside a try/except that catches ImportError."""
    for parent in ast.walk(tree):
        if not isinstance(parent, ast.Try):
            continue
        # Does this try contain our node?
        for child in ast.walk(parent):
            if child is node:
                # Now check the except clauses
                for handler in parent.handlers:
                    if handler.type is None:
                        return True  # bare except: catches everything
                    # Single exception
                    if isinstance(handler.type, ast.Name):
                        if handler.type.id in ("ImportError", "ModuleNotFoundError",
                                                "Exception", "BaseException"):
                            return True
                    # Tuple of exceptions
                    elif isinstance(handler.type, ast.Tuple):
                        for elt in handler.type.elts:
                            if isinstance(elt, ast.Name) and elt.id in (
                                "ImportError", "ModuleNotFoundError",
                                "Exception", "BaseException"
                            ):
                                return True
                return False
    return False


def _closest_match(name: str, available: list[str], n: int = 1) -> str | None:
    matches = difflib.get_close_matches(name, available, n=n, cutoff=0.7)
    return matches[0] if matches else None


def _check_import_from(
    node: ast.ImportFrom,
    tree: ast.AST,
    rel_path: str,
    repo_root: str,
    source_lines: list[str],
    now: datetime,
) -> List[Verdict]:
    out: List[Verdict] = []
    if node.module is None or node.level > 0:
        return out  # relative — skip
    if node.module not in ALLOWLIST_PACKAGES:
        return out
    if _is_optional_import_context(node, tree):
        return out

    module = _safe_import(node.module)
    if module is None:
        return out  # package not installed in scan env — skip rather than FP

    # Build the available-attributes set once.
    available = [a for a in dir(module) if not a.startswith("_")]
    avail_set = set(available)

    for alias in node.names:
        name = alias.name
        if name == "*":
            continue
        if name in avail_set:
            continue
        # `from X import Y` also succeeds when Y is a SUBMODULE of X
        # (Python's import system imports the submodule on the fly).
        # `getattr(unittest, 'mock')` is False until something imports
        # unittest.mock, but `from unittest import mock` works regardless.
        # Verify via find_spec rather than triggering the import.
        try:
            sub_spec = importlib.util.find_spec(f"{node.module}.{name}")
            if sub_spec is not None:
                continue
        except (ImportError, ValueError, AttributeError):
            pass
        # Hallucinated. Suggest closest match.
        line_no = node.lineno
        cur = source_lines[line_no - 1] if line_no - 1 < len(source_lines) else ""
        prv = source_lines[line_no - 2] if line_no - 2 >= 0 else ""
        if line_is_suppressed(cur, prv, ID):
            continue
        suggestion = _closest_match(name, available)
        suggest_hint = f" — did you mean `{node.module}.{suggestion}`?" if suggestion else ""
        out.append(Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=repo_root,
            file=rel_path,
            line=line_no,
            detail=(
                f"`from {node.module} import {name}` — `{name}` is not an "
                f"attribute of `{node.module}` (hallucinated import){suggest_hint}"
            ),
            fix_hint=(
                f"check the package's actual exports; common LLM mistakes "
                "include renaming snake_case ↔ original or fabricating "
                "function names by analogy"
            ),
            source=SOURCE,
            timestamp=now,
        ))
    return out


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    root = ctx.repo_root
    for path in iter_repo_files(root, "*.py", PY_EXCLUDE_DIRS, population=POPULATION):
        if has_skip_marker(path):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Cheap pre-filter: only parse files with `from ` import lines.
        if "from " not in text:
            continue
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError:
            continue  # parse errors are P1-py-parse-check's job
        rel = path.relative_to(root).as_posix()
        lines = text.splitlines()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                verdicts.extend(_check_import_from(
                    node, tree, rel, str(root), lines, now,
                ))
    return verdicts
