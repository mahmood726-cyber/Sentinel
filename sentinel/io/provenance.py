"""Provenance stamping for findings: which COMMIT, and was the file TRACKED.

Why this exists (2026-08-30, historical-replay run):

A replay of 452 historical BLOCK findings against the commit each was recorded
at could not anchor any of them, because a finding carried only a `timestamp`.
The commit had to be RECONSTRUCTED as `git rev-list -n1 --before=<ts> HEAD`,
which is a guess dressed as provenance.

Worse, 12 of 19 apparent "detector gaps" turned out to be findings against
files that exist in NO commit at all -- Sentinel scans the working tree,
including untracked files, so a working-tree finding was indistinguishable
from a committed one. That ambiguity manufactured 18 false accusations against
the rule set; a hand-check of a single case collapsed them to 0.

Two fields retire both misreadings:

  commit   the repo HEAD at scan time, so a finding names the artefact version
           it was raised against instead of leaving it to be inferred.
  tracked  whether the file was in `git ls-files` at scan time, so a finding
           about an untracked file is never mistaken for one about a commit.

Both are stamped at serialisation, so `Verdict` stays frozen and no rule has to
change. Both are best-effort: outside a git repo they are recorded as None,
which is an honest "unknown", never a fabricated value.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Dict, Optional

_GIT_TIMEOUT = 15

# per-process caches, keyed by resolved repo root
_commit_cache: Dict[str, Optional[str]] = {}
_tracked_cache: Dict[str, Optional[frozenset]] = {}


def _git(root: Path, *args: str) -> Optional[str]:
    try:
        r = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True, text=True, timeout=_GIT_TIMEOUT,
            stdin=subprocess.DEVNULL, errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return (r.stdout or "").strip()


def head_commit(repo_root: Path) -> Optional[str]:
    """Full SHA of HEAD, or None outside a git repo / on an empty repo."""
    key = str(Path(repo_root).resolve())
    if key not in _commit_cache:
        out = _git(Path(repo_root), "rev-parse", "HEAD")
        _commit_cache[key] = out or None
    return _commit_cache[key]


def tracked_files(repo_root: Path) -> Optional[frozenset]:
    """Set of repo-relative posix paths tracked at scan time, or None if the
    set could not be determined (outside git). None is NOT an empty set -- an
    empty set would wrongly mark every file untracked."""
    key = str(Path(repo_root).resolve())
    if key not in _tracked_cache:
        out = _git(Path(repo_root), "ls-files")
        if out is None:
            _tracked_cache[key] = None
        else:
            _tracked_cache[key] = frozenset(
                line.strip() for line in out.split("\n") if line.strip()
            )
    return _tracked_cache[key]


def is_tracked(repo_root: Path, rel_file: Optional[str]) -> Optional[bool]:
    """True/False if we know, None if the file is unknown or not applicable
    (repo-wide findings carry no file)."""
    if not rel_file:
        return None
    files = tracked_files(repo_root)
    if files is None:
        return None
    return rel_file.replace("\\", "/").lstrip("./") in files


def stamp(repo_root: Path, record: dict, rel_file: Optional[str]) -> dict:
    """Add `commit` and `tracked` to a serialised finding, in place."""
    record["commit"] = head_commit(repo_root)
    record["tracked"] = is_tracked(repo_root, rel_file)
    return record


def _reset_caches_for_tests() -> None:
    """Test hook: the caches are per-process and keyed by path, so a test that
    reuses a tmp_path name across repos would otherwise see a stale answer."""
    _commit_cache.clear()
    _tracked_cache.clear()
