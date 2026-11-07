# sentinel:skip-file - this module's docstring quotes an absolute path as the
# EXAMPLE of what a RECORD-role file legitimately contains, so it self-flags.
# Same dogfooding carve-out as sentinel/io/git_files.py.
"""File ROLE — what a file is for — as the scoping axis for every rule.

WHY NOT "IS GIT TRACKING IT"

Tracked-ness was doing this job by accident and doing it badly: it describes
git's state, not whether a file is a deliverable. On F:/E156 it produced a
155-verdict backlog of which 84.5% sat in untracked lane notes, while a rule
that encodes a real incident (`P1-module-stdout-reassign`) returned 0 against
the one file carrying that exact defect -- because the file was untracked.

A rule needs to know two different things and they are not the same question:

    POPULATION  which files exist for this scan  -> sentinel/io/population.py
    ROLE        what this file is FOR            -> here

ROLES

    SHIPPED   code and documentation a consumer receives, runs, or follows.
              Every rule applies. This is the DEFAULT for anything unclassified,
              because a role system that defaults to exempt is how a suite goes
              inert.

    RECORD    authored, kept for provenance, never executed: dated lane notes,
              session records, audit reports. An absolute path here is DATA
              ("the run happened at C:/Projects/x on pc2"), not a portability
              break. Sentinel already carved this out ad hoc per rule --
              `wiki/**`, `data/nightly_reports/**`, `vault/**`, `harness/**`.
              This generalises it and makes it one decision instead of N.

    SCRATCH   working files with no consumer: burn dirs, captured process
              output, probe scratch.

DECLARING ROLES: `.sentinel-roles` at the repo root

    # glob                     role
    _burn/**                   scratch
    *.md                       record
    README.md                  shipped

LAST MATCH WINS, so the file reads top-to-bottom as increasingly specific
overrides. Globs mean NOTHING HAS TO MOVE to adopt a convention -- a directory
layout is the tidier long-term form, but it is not a precondition.

With no `.sentinel-roles` present every file is SHIPPED and every rule behaves
exactly as it does today. Adopting roles is opt-in, per repo, and visible in
one auditable file.
"""
from __future__ import annotations

import fnmatch
from enum import Enum
from pathlib import Path
from typing import Optional

ROLES_FILENAME = ".sentinel-roles"


class Role(str, Enum):
    SHIPPED = "shipped"
    RECORD = "record"
    SCRATCH = "scratch"


ALL_ROLES = frozenset(Role)
DEFAULT_ROLE = Role.SHIPPED

# Applied only when the repo has no `.sentinel-roles`. Deliberately tiny: it
# covers directory names that are scratch by universal convention, and nothing
# that could plausibly be a deliverable.
BUILTIN_SCRATCH_GLOBS = ("_burn/**", "_tmp/**", "_scratch/**")


def _match(rel: str, pat: str) -> bool:
    if fnmatch.fnmatch(rel, pat):
        return True
    stripped = pat
    while stripped.startswith("**/"):
        stripped = stripped[3:]
    return stripped != pat and fnmatch.fnmatch(rel, stripped)


class RoleMap:
    """Ordered (glob, role) rules; last match wins."""

    def __init__(self, entries: list[tuple[str, Role]], source: str):
        self.entries = entries
        self.source = source

    @classmethod
    def load(cls, repo_root: Path) -> "RoleMap":
        path = repo_root / ROLES_FILENAME
        if not path.is_file():
            return cls([(g, Role.SCRATCH) for g in BUILTIN_SCRATCH_GLOBS],
                       source="(built-in defaults; no .sentinel-roles)")
        entries: list[tuple[str, Role]] = []
        try:
            text = path.read_bytes().decode("utf-8", errors="replace")
        except OSError:
            return cls([], source=f"({ROLES_FILENAME} unreadable)")
        for lineno, line in enumerate(text.splitlines(), 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            glob, name = parts[0], parts[-1].lower()
            try:
                entries.append((glob.replace("\\", "/"), Role(name)))
            except ValueError:
                # An unknown role name must not silently become an exemption.
                continue
        return cls(entries, source=ROLES_FILENAME)

    def role_of(self, rel: str) -> Role:
        rel = rel.replace("\\", "/")
        role = DEFAULT_ROLE
        for glob, r in self.entries:
            if _match(rel, glob):
                role = r
        return role

    def census(self, rels) -> dict:
        out = {r.value: 0 for r in Role}
        for rel in rels:
            out[self.role_of(rel).value] += 1
        return out


def load_roles(repo_root: Path) -> RoleMap:
    return RoleMap.load(repo_root)


def parse_roles_declaration(value) -> frozenset:
    """Normalise a rule's ROLES declaration into a frozenset of Role.

    A rule that declares nothing gets ALL roles -- it keeps applying
    everywhere, so adding this machinery cannot make an existing rule quieter
    by omission.
    """
    if value is None:
        return ALL_ROLES
    if isinstance(value, (str, Role)):
        value = [value]
    out = set()
    for v in value:
        try:
            out.add(v if isinstance(v, Role) else Role(str(v).lower()))
        except ValueError:
            continue
    return frozenset(out) if out else ALL_ROLES
