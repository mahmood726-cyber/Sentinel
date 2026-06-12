"""P1-py-package-init-tracked: WARN when a directory has files using relative
imports but its `__init__.py` package marker is not tracked in git.

Triggering incident (2026-04-28 portfolio audit):
  - CardioOracle: curate/extract_aact.py used `from .shared import ...`
    but curate/__init__.py existed only on disk, never staged. Fresh
    clones hit ImportError on step 1 of the README's reproduce recipe.
  - Same gap caught in 5 other repos by the same audit:
    TrialAtlas (src), Dataextractor (python/rctextractor),
    KMcurve (ipd_km_pipeline/metadata),
    llm-meta-analysis (evaluation/models — file didn't even exist on disk),
    meta-paradigm-shift (src).

Why it's invisible during dev: cwd + sys.path tricks make local imports
work even when __init__.py is unstaged. The break only shows up on a
fresh clone or a CI runner.

Detection:
  For each TRACKED *.py file whose top-level imports include
  `from .X import` or `from ..X import`, check whether
  `<dir>/__init__.py` is tracked in git. Untracked .py files (e.g.
  inside .cmdstan/, .positron/extensions/, AppData/Local/pypa/, OneDrive
  backups) are skipped — fresh clones don't see them at all, so they
  can't ImportError on them. If the directory is itself inside a path
  that already has an ancestor __init__.py tracked, that's fine — the
  parent makes it a sub-package.

Severity: WARN (not BLOCK).
  - Lots of legitimate src-layouts use unconventional package markers.
  - Editable installs and namespace packages (PEP 420) intentionally
    omit __init__.py.
  - Until we have a year of production data on this rule, BLOCK risks
    too many false positives.
  Promote to BLOCK in a future sweep if WARN volume is consistently low
  AND the false-positive rate is below 5%.

Skip:
  - Vendored / third-party trees (vendor/, third_party/, node_modules/).
  - Build / venv dirs (build/, dist/, .venv/, venv/, .tox/).
  - Worktree dirs (.worktrees/) — those are separate repos.
  - Test files inside tests/ are flagged only if their tests/ dir uses
    relative imports between test modules (rare).

Fix hint: `git add <dir>/__init__.py` (creating an empty file first if it
does not exist).
"""
from __future__ import annotations

import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Set

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import path_allowed


ID = "P1-py-package-init-tracked"
SEVERITY = Severity.WARN
SOURCE = "lessons.md#portfolio-audit-patterns"
SCOPE = "repo"

REL_IMPORT_RE = re.compile(r"^\s*from\s+\.+\w*\s+import\s", re.MULTILINE)

SKIP_DIR_NAMES: Set[str] = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
    ".pytest_cache", ".pytest_tmp", "build", "dist", ".tox", ".mypy_cache",
    "site-packages", "vendor", "third_party", ".worktrees",
}


def _list_tracked(repo: Path) -> Set[str]:
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "ls-files"],
            capture_output=True, text=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return set()
    if r.returncode != 0:
        return set()
    return set(r.stdout.splitlines())


def _walk_py_dirs(repo: Path, tracked: Set[str]):
    """Yield (relative_dir_path, evidence_filename) for each directory
    that contains at least one TRACKED .py file using relative imports.
    Untracked files are skipped — fresh clones don't see them, so they
    cannot trigger ImportError on a clone."""
    import os
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        py_files = [n for n in filenames if n.endswith(".py")]
        if not py_files:
            continue
        rel_dir = Path(dirpath).relative_to(repo).as_posix() or "."
        uses_relative = False
        evidence_file = None
        for fname in py_files:
            tracked_key = fname if rel_dir == "." else f"{rel_dir}/{fname}"
            if tracked_key not in tracked:
                continue
            if not path_allowed(repo, Path(dirpath) / fname):
                continue  # honor `scan --diff` changed-file scope
            try:
                text = (Path(dirpath) / fname).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if REL_IMPORT_RE.search(text):
                uses_relative = True
                evidence_file = fname
                break
        if uses_relative:
            yield rel_dir, evidence_file


def check(ctx: RepoContext) -> List[Verdict]:
    repo = ctx.repo_root
    if not (repo / ".git").is_dir():
        return []

    tracked = _list_tracked(repo)
    if not tracked:
        return []

    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []

    for rel_dir, evidence in _walk_py_dirs(repo, tracked):
        init_rel = f"{rel_dir}/__init__.py" if rel_dir != "." else "__init__.py"
        if init_rel in tracked:
            continue

        evidence_path = f"{rel_dir}/{evidence}" if rel_dir != "." else evidence

        verdicts.append(Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=str(repo),
            file=evidence_path,
            line=None,
            detail=(
                f"{rel_dir}/ uses relative imports (see {evidence}) but "
                f"{init_rel} is not tracked in git — fresh clones will "
                "ImportError"
            ),
            fix_hint=(
                f"create the file if missing, then `git add {init_rel}`"
            ),
            source=SOURCE,
            timestamp=now,
        ))

    return verdicts
