"""P2-reuse-available: WARN when a file hand-rolls a primitive that already
exists in a shared offline kit -- so the author copies it (zero tokens) instead
of asking an agent to regenerate it (thousands of tokens).

WHY THIS EXISTS (the reuse incident):
  The portfolio has repeatedly grown near-duplicate code -- ">=3 near-duplicate
  atlases" and multiple hand-rolled forest/funnel-plot renderers -- because an
  agent regenerated a chart or a loader from scratch rather than reusing the
  shared kit. That wastes tokens on the way in (regeneration) AND on the way out
  (every future agent must re-read the duplicate). `rules.md` already mandates
  "reuse vs net-new" recon, and `e156-ecosystem-starter/scripts/reuse.py` makes
  the existing primitives queryable offline. This rule turns that honor-system
  guidance into a commit-time nudge.

WHAT IT FLAGS (high-signal, low-false-positive by design):
  Only DISTINCTIVE kit primitives detected by their unmistakable definition
  contract, never by a generic name alone:
    - e156-chart-kit: a JS function `renderX(svgEl, ...)` whose name is one of the
      kit's chart primitives. The literal first parameter `svgEl` is the kit's
      contract -- a coincidental `renderBars(ctx, data)` elsewhere will NOT match.
    - aact-kit: `class AACTLocation/AACTBackend/AACTSchemaError` or
      `def resolve_aact_location(...)` -- the `AACT`/`resolve_aact_` names are
      distinctive enough on their own.

SEVERITY — stays WARN (not a BLOCK candidate). A 2026-06-05 portfolio sweep ran
this rule across 709 repos (C:/Projects + C:/Users/mahmo/code + C:/E156): zero
false positives AND zero true positives. The leaked_secret precedent promotes a
rule to BLOCK only when it catches a real ship-blocking defect; this is a
token/quality advisory, and hard-blocking a push over a reuse suggestion is a
sharp edge for no benefit. It is a high-precision regression guard (the exact
kit contract, verbatim) — real reimplementations use different names
(`drawForest`, not `renderForest`), so near-zero recall is expected and is the
correct trade: the reuse value is delivered proactively by `reuse.py find` and
the handoff prompts, with this rule as a cheap, zero-FP safety net. Do NOT chase
recall with fuzzy structural detection — that would reintroduce false positives.

FALSE-POSITIVE DISCIPLINE:
  - Skips any file that already REFERENCES the owning kit (imports it, or mentions
    `chartkit` / `chart-kit` / `aact_kit` / `aact-kit`): if you reference the kit,
    you're using/extending it, not reimplementing it. This also exempts the kits'
    own source files.
  - Skips kit-owned paths, generated/vendored/archived dirs, and test files.
  - `sentinel:skip-file` suppresses (intentional bespoke implementation).
  - Inert on any file with no primitive definition (zero findings).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import iter_tree_or_filter
from sentinel.io.population import Population
from sentinel.io.skip_marker import has_skip_marker

ID = "P2-reuse-available"
SEVERITY = Severity.WARN
SOURCE = "rules.md#portfolio-recon-before-any-new-project"
SCOPE = "repo"

# Population: PRESENT -- tracked AND untracked-not-ignored.
#
# This rule walked the raw filesystem: every path under the repo root. On
# F:/E156 that is 49,079 files against PRESENT's 4,246, and 91.3% of the
# excess is .git internals, caches and build output that no push can
# ship. Migrated 2026-08-30. Counts from before that date were taken over
# a DIFFERENT and larger file set and are NOT comparable with counts
# after it.
POPULATION = Population.PRESENT

MAX_FILE_BYTES = 2_000_000
INCLUDE_EXT = frozenset((".js", ".py", ".html", ".htm"))

EXCLUDE_DIRS = frozenset((
    "node_modules", "__pycache__", ".git", ".pytest_cache", ".venv", "venv",
    "build", "dist", ".tox", ".mypy_cache", "vendor", "archive",
    "release-snapshots", "tests", "test",
))
FROZEN_DIR_PREFIXES = ("backup_", "backup-")

# Path tokens that mark a file as belonging to (or vendoring) one of the kits
# themselves -- never flag the kit's own primitive definitions.
KIT_PATH_TOKENS = ("chart-kit", "chartkit", "aact-kit", "aact_kit",
                   "rapidmeta-kit", "e156-capsule")

# A file that references the owning kit by import/name is USING it, not
# reimplementing it. (Also exempts the kit's own files, which name themselves.)
_KIT_REFERENCE_RE = re.compile(
    r"chartkit|chart-kit|\baact_kit\b|aact-kit|e156-chart-kit", re.IGNORECASE)

# e156-chart-kit primitives. The kit's contract is `renderX(svgEl, ...)`; we key
# on that literal first parameter so a same-named function with a different first
# arg (a coincidence) never matches. Derived from chartkit.js public render* API.
CHART_PRIMITIVES = (
    "renderForest", "renderGroupedForest", "renderFunnel", "renderLOO",
    "renderCumulative", "renderSubgroup", "renderBubble", "renderGOSH",
    "renderNetwork", "renderRanking", "renderRankogram", "renderSROC",
    "renderDensity", "renderKM", "renderCEplane", "renderScatter", "renderBars",
    "renderLovePlot", "renderCurve", "renderROC", "renderCalibration",
    "renderTrafficLight", "renderStackedBar", "renderStackedArea", "renderGauge",
    "renderInterval", "renderSankey",
)
# function renderX(svgEl ...   |   renderX = function(svgEl   |   renderX: function(svgEl
# renderX = (svgEl ...) =>     |   renderX:(svgEl
_CHART_NAME_ALT = "|".join(re.escape(n) for n in CHART_PRIMITIVES)
_CHART_DEF_RE = re.compile(
    r"(?:function\s+(?P<n1>" + _CHART_NAME_ALT + r")\s*\(\s*svgEl\b"
    r"|\b(?P<n2>" + _CHART_NAME_ALT + r")\s*[:=]\s*(?:async\s+)?(?:function\s*)?\(\s*svgEl\b)"
)

# aact-kit primitives -- distinctive enough by name alone.
_AACT_DEF_RE = re.compile(
    r"\bclass\s+(?P<c>AACTLocation|AACTBackend|AACTSchemaError)\b"
    r"|\bdef\s+(?P<d>resolve_aact_location)\b"
)

_INSTALL_HINT = {
    "e156-chart-kit": "install-e156-capsules",
    "aact-kit": "install-aact-kit",
}


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _iter_files(root: Path):
    for path in iter_tree_or_filter(root, population=POPULATION):  # changed-file scope under --diff
        if not path.is_file():
            continue
        if path.suffix.lower() not in INCLUDE_EXT:
            continue
        parts_lower = [p.lower() for p in path.parts]
        if any(d in EXCLUDE_DIRS for d in parts_lower):
            continue
        if any(p.startswith(FROZEN_DIR_PREFIXES) for p in parts_lower):
            continue
        # Kit-owned / vendored copies of a kit: never flag the kit's own defs.
        if any(tok in part for part in parts_lower for tok in KIT_PATH_TOKENS):
            continue
        yield path


def _first_match(text: str):
    """Return (primitive_name, kit, match) for the first reimplementation, or None."""
    chart = _CHART_DEF_RE.search(text)
    aact = _AACT_DEF_RE.search(text)
    candidates = []
    if chart is not None:
        name = chart.group("n1") or chart.group("n2")
        candidates.append((chart.start(), name, "e156-chart-kit", chart))
    if aact is not None:
        name = aact.group("c") or aact.group("d")
        candidates.append((aact.start(), name, "aact-kit", aact))
    if not candidates:
        return None
    candidates.sort(key=lambda c: c[0])
    _, name, kit, match = candidates[0]
    return name, kit, match


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    root = ctx.repo_root
    verdicts: List[Verdict] = []
    for path in _iter_files(root):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        if has_skip_marker(path):
            continue
        # Referencing the kit == using/extending it, not reimplementing.
        if _KIT_REFERENCE_RE.search(text):
            continue

        found = _first_match(text)
        if found is None:
            continue
        name, kit, match = found
        hint = _INSTALL_HINT.get(kit, "")
        get_it = f" (get it: {hint})" if hint else ""
        rel = path.relative_to(root).as_posix()
        verdicts.append(Verdict(
            rule_id=ID,
            severity=Severity.WARN,
            repo=str(root),
            file=rel,
            line=_line_of(text, match.start()),
            detail=(
                f"`{name}` already exists in the shared kit `{kit}`{get_it} -- this "
                f"file appears to reimplement it. Copy the existing primitive "
                f"instead of regenerating it (regenerating costs an agent thousands "
                f"of tokens; copying costs zero)."
            ),
            fix_hint=(
                f"run `python scripts/reuse.py find \"{name}\"` in e156-ecosystem-starter "
                f"to get the exact signature and source to copy; if this bespoke "
                f"implementation is intentional, add a `sentinel:skip-file` marker"
            ),
            source=SOURCE,
            timestamp=now,
        ))
    return verdicts
