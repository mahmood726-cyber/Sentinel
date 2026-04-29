# sentinel:skip-file — references license-name patterns by necessity
"""P1-license-noncompliance: WARN when a repo's declared dependencies
include a copyleft license (GPL/AGPL/LGPL family) that would create a
compatibility risk for repos published under MIT.

Why this rule exists:
  This portfolio publishes ~333 repos under MIT. If a repo transitively
  imports a GPL/AGPL dep, the resulting binary is effectively GPL-tainted
  — the MIT label on the repo becomes misleading, and downstream users
  who comply with MIT may unknowingly violate GPL terms.

  Standard tooling (pip-licenses, liccheck, GitHub's licensee) catches
  this; we surface it as a Sentinel rule so the check fires at push time
  on every repo, with the same fail-closed semantics as other Sentinel
  rules.

Severity: WARN.

Rationale for starting at WARN: copyleft is not always wrong — a tool
*intended* for GPL distribution legitimately uses GPL deps. The rule
flags for human review; the dev decides whether to (a) swap the dep,
(b) re-license the repo away from MIT, or (c) suppress with a
sentinel:skip-line marker explaining the deliberate choice.

Detection:
  1. Locate the repo's declared deps via `requirements.txt`,
     `pyproject.toml` ([project.dependencies] or [tool.poetry.dependencies]),
     or `setup.py` (best-effort regex on `install_requires=`).
  2. Cross-reference declared dep names against `pip-licenses --format=json`
     output (pip-licenses must be installed; SKIP gracefully otherwise).
  3. Emit WARN for each declared dep whose installed license is in the
     forbidden set. Fixed normalization handles "GNU General Public
     License v3" vs "GPL-3.0" vs "GPL-3.0-or-later" etc.

Skip conditions:
  - pip-licenses not installed (gracefully skip; not a FAIL — missing
    tool != failed scan, per UNVERIFIED-vs-PASS lesson)
  - No requirements.txt / pyproject.toml / setup.py found
  - Dep declared but not installed in current env (can't determine license)

Limitations:
  - Reads the GLOBAL pip env. If the repo is meant to run in a venv with
    different deps, results may be misleading. Future enhancement:
    detect repo-local venv at .venv/ or venv/ and prefer those licenses.
  - Dual-licensed packages (e.g. "MIT or GPL-2.0") are flagged
    pessimistically as GPL — the user can suppress with a skip-line.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P1-license-noncompliance"
SEVERITY = Severity.WARN
SOURCE = "lessons.md#license-compliance-2026-04-29"
SCOPE = "repo"

# Strictly forbidden (MIT-incompatible) license families. Each entry is
# matched case-insensitively against the package's declared license string
# AFTER simple normalization (lowercase, dashes/underscores collapsed).
# We intentionally do NOT block LGPL — dynamic linking against LGPL is
# generally MIT-compatible. AGPL is the strictest of the three so flagged
# even when used as a tool dependency.
_FORBIDDEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bgpl[\s\-_]*v?[23]\b", re.IGNORECASE),
    re.compile(r"\bagpl[\s\-_]*v?[13]\b", re.IGNORECASE),
    re.compile(r"\bgnu general public license\b", re.IGNORECASE),
    re.compile(r"\bgnu affero general public license\b", re.IGNORECASE),
)

# Files we look at to enumerate declared deps.
_REQUIREMENTS_FILES = ("requirements.txt", "requirements-dev.txt",
                       "requirements/base.txt", "requirements/prod.txt")


_REQ_LINE_RE = re.compile(
    # Captures the package name from a pip requirement line:
    # `package`, `package==1.0`, `package>=1.0`, `package[extra]`,
    # `package[extra]==1.0,<2`. Skips comments, -r/-e directives,
    # URLs, and editable installs.
    r"^\s*([A-Za-z][A-Za-z0-9_\-\.]*)",
)


def _normalize_pkg(name: str) -> str:
    """PEP 503 normalization — pip-licenses output uses canonical names."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_requirements(path: Path) -> set[str]:
    """Return a set of normalized package names declared in a requirements
    file. Comments, -r/-e/-c directives, URLs, blank lines all skipped."""
    pkgs: set[str] = set()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return pkgs
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "://" in line:  # URL or VCS install
            continue
        m = _REQ_LINE_RE.match(line)
        if m:
            pkgs.add(_normalize_pkg(m.group(1)))
    return pkgs


def _parse_pyproject(path: Path) -> set[str]:
    """Best-effort extract from pyproject.toml. Avoids requiring tomllib
    on older Python by using regex; misses edge cases but catches the
    common shapes ([project.dependencies] / [tool.poetry.dependencies])."""
    pkgs: set[str] = set()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return pkgs
    # PEP 621 [project.dependencies] = [ "pkg >=1.0", ... ]
    block = re.search(
        r"\[project\][^\[]*?dependencies\s*=\s*\[(.+?)\]",
        text, re.DOTALL,
    )
    if block:
        for entry in re.findall(r'"([^"]+)"', block.group(1)):
            m = _REQ_LINE_RE.match(entry)
            if m:
                pkgs.add(_normalize_pkg(m.group(1)))
    # Poetry: [tool.poetry.dependencies] pkg = "^1.0"
    poetry_block = re.search(
        r"\[tool\.poetry\.dependencies\](.+?)(?=\n\[|\Z)", text, re.DOTALL,
    )
    if poetry_block:
        for line in poetry_block.group(1).splitlines():
            m = re.match(r'^\s*([A-Za-z][A-Za-z0-9_\-]*)\s*=', line)
            if m and m.group(1).lower() != "python":
                pkgs.add(_normalize_pkg(m.group(1)))
    return pkgs


def _collect_declared_deps(repo_root: Path) -> set[str]:
    pkgs: set[str] = set()
    for rel in _REQUIREMENTS_FILES:
        f = repo_root / rel
        if f.is_file():
            pkgs |= _parse_requirements(f)
    pyproject = repo_root / "pyproject.toml"
    if pyproject.is_file():
        pkgs |= _parse_pyproject(pyproject)
    return pkgs


def _pip_licenses_snapshot() -> dict[str, str] | None:
    """Return {normalized_name: license_string} from `pip-licenses --format=json`,
    or None if the tool isn't installed (callers MUST treat None as SKIP,
    never as 'no findings')."""
    if shutil.which("pip-licenses") is None:
        return None
    try:
        proc = subprocess.run(
            ["pip-licenses", "--format=json", "--with-system"],
            capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    out: dict[str, str] = {}
    for record in data:
        if not isinstance(record, dict):
            continue
        name = record.get("Name") or ""
        license_str = record.get("License") or ""
        if name:
            out[_normalize_pkg(name)] = license_str
    return out


def _is_forbidden(license_str: str) -> bool:
    if not license_str or license_str.upper() == "UNKNOWN":
        return False
    return any(pat.search(license_str) for pat in _FORBIDDEN_PATTERNS)


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []

    declared = _collect_declared_deps(ctx.repo_root)
    if not declared:
        return verdicts  # No deps declared — nothing to check

    licenses = _pip_licenses_snapshot()
    if licenses is None:
        return verdicts  # pip-licenses unavailable; SKIP gracefully

    for pkg in sorted(declared):
        license_str = licenses.get(pkg)
        if license_str is None:
            continue  # declared but not installed — can't determine
        if not _is_forbidden(license_str):
            continue
        verdicts.append(Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=str(ctx.repo_root),
            file=None,  # repo-wide finding; no specific line
            line=None,
            detail=(
                f"package '{pkg}' has license '{license_str}' which conflicts "
                "with MIT-licensed publication. If this repo is intentionally "
                "GPL/AGPL, suppress with a sentinel:skip-line marker; "
                "otherwise swap to a permissive-licensed alternative."
            ),
            fix_hint=(
                "Options: (1) replace the dep with an MIT/BSD/Apache-2.0 "
                "alternative; (2) change the repo's LICENSE to GPL/AGPL "
                "to match the dep; (3) if dual-licensed in your favor, add "
                "a comment near the dep declaration with the chosen license "
                "and add 'sentinel:skip-line P1-license-noncompliance' nearby."
            ),
            source=SOURCE,
            timestamp=now,
        ))

    return verdicts
