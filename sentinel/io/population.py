"""One definition of "the files in this repo" — for BOTH rule families.

WHY THIS MODULE EXISTS (measured 2026-08-30, F:/E156):

  Sentinel had two file-set functions that disagreed, and neither said so:

    iter_repo_files()      (sentinel/io/git_files.py)   -- plugin rules, 57 of 64
        git ls-files -- <patterns>                      -> TRACKED ONLY
    _git_tracked_files()   (registry/yaml_loader.py)    -- yaml rules, 7 of 64
        git ls-files --cached --others --exclude-standard -> TRACKED + UNTRACKED

  Proven on one file with identical bytes:

        state                      plugin rule    yaml rule
        untracked (not ignored)         0             1
        tracked                         1             1

  Consequences on the live repo: every one of the 155 BLOCK verdicts came from
  a single YAML rule, 131 of them (84.5%) in untracked files that no plugin
  rule can see; and P1-module-stdout-reassign returned 0 against
  rapidmeta-xcheck-2026-07-18/prep.py, which carries the exact unguarded
  `sys.stdout = io.TextIOWrapper(...)` incident the rule encodes -- solely
  because the file is untracked.

  A rule that cannot see the case it was written for is decorative. But
  "tracked" is a bad proxy in the other direction too: it describes git's
  state, not whether a file is a deliverable.

THE RESOLUTION: two questions, two populations, named explicitly.

  PUBLISHED -- what the world can read. For a PUBLIC repo that is exactly the
               tracked set: every commit is served by the host, so a secret or
               a home-directory path in a tracked file is a real disclosure.
               Disclosure rules (paths, secrets, config leaks) read this.

  PRESENT   -- everything on disk that git is not ignoring, tracked or not.
               A defect in an untracked script still runs when someone runs it.
               Correctness rules (parse errors, stdout reassignment, unsafe
               eval, empty-dataframe access) read this.

  Neither is "the repo". A rule must say which question it is asking.

DEFAULT: PRESENT. A rule author who does not declare gets the larger set --
the noisier, safer failure. Going quiet by omission is how a suite goes inert.
"""
from __future__ import annotations

import subprocess
from enum import Enum
from pathlib import Path
from typing import Optional


class Population(str, Enum):
    """Which file set a rule reads. See module docstring."""

    PUBLISHED = "published"   # git ls-files --cached
    PRESENT = "present"       # git ls-files --cached --others --exclude-standard


_ARGS = {
    Population.PUBLISHED: ("--cached",),
    Population.PRESENT: ("--cached", "--others", "--exclude-standard"),
}

_TIMEOUT = 60


def is_git_worktree(root: Path) -> bool:
    """`.git` may be a directory (normal repo) or a file (submodule / linked
    worktree carrying `gitdir: ...`)."""
    return (root / ".git").exists()


def repo_files(root: Path, population: Population = Population.PRESENT
               ) -> Optional[frozenset[str]]:
    """Forward-slash relative paths in `population`, or None when `root` is not
    a git worktree (callers fall back to a bounded rglob).

    Fails CLOSED on any git failure inside a worktree -- returns an empty set,
    never a tree walk. An rglob fallback inside a broken worktree re-opens the
    home-directory DoS that git_files.py exists to close (2026-04-19).
    """
    if not is_git_worktree(root):
        return None
    try:
        res = subprocess.run(
            ["git", "-C", str(root), "-c", "core.quotePath=false",
             "ls-files", "-z", *_ARGS[population]],
            capture_output=True, timeout=_TIMEOUT,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return frozenset()
    if res.returncode != 0:
        return frozenset()
    try:
        out = res.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return frozenset()
    return frozenset(e.replace("\\", "/") for e in out.split("\0") if e)


def coverage(root: Path) -> dict:
    """Numbers for the runner's coverage line.

    Printing this is the point: a verdict count means nothing without the
    population it was counted over, and until now the two rule families were
    counting over different ones without either saying which.
    """
    pub = repo_files(root, Population.PUBLISHED)
    pres = repo_files(root, Population.PRESENT)
    if pub is None or pres is None:
        return {"git": False, "published": None, "present": None,
                "present_only": None}
    return {
        "git": True,
        "published": len(pub),
        "present": len(pres),
        "present_only": len(pres - pub),
    }
