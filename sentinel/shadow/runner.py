"""Shadow runner — execute the enforcing regex rules and the AST matchers over
the same files, and diff their findings.

This is measurement scaffolding, not an enforcing path. It loads the three
regex plugins the ordinary way (so the "regex" column is EXACTLY what Sentinel
ships) and runs the AST matchers from `sentinel.shadow.ast_matchers` over the
same Python sources. Both verdict sets are logged; nothing here blocks a push.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, List, Optional

from sentinel.core import RepoContext, ScanMode
from sentinel.io.git_files import PY_EXCLUDE_DIRS, iter_repo_files
from sentinel.io.skip_marker import has_skip_marker
from sentinel.registry.plugin_loader import load_plugin_rule
from sentinel.shadow.ast_matchers import (
    ShadowFinding,
    ast_insecure_deserialization,
    ast_leaked_secret,
    ast_unsafe_eval_exec,
)

_PLUGINS_DIR = Path(__file__).resolve().parent.parent / "rules" / "plugins"

# rule_id -> (regex plugin filename, AST matcher fn)
RULES: dict[str, tuple[str, Callable[[str, str], List[ShadowFinding]]]] = {
    "P0-unsafe-eval-exec": ("unsafe_eval_exec.py", ast_unsafe_eval_exec),
    "P1-leaked-secret": ("leaked_secret.py", ast_leaked_secret),
    "P1-insecure-deserialization": ("insecure_deserialization.py", ast_insecure_deserialization),
}

_EXCLUDE_PARTS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv", "site-packages",
    ".tox", ".eggs", "build", "dist", ".pytest_cache", "archive",
    ".mypy_cache", "vendor",
})

MAX_FILE_BYTES = 2_000_000

# Files with a line this long are minified blobs / embedded data, not source —
# and they are exactly where `_strip_noise`'s DOTALL string regex catastrophically
# backtracks (see report §5). We skip the regex-side noise-strip on them and
# COUNT the skips so the measurement is honest. The AST side (ast.parse, O(n)) is
# unaffected and still runs.
LONG_LINE_LIMIT = 3000

# Credential-prefix tokens the leaked_secret plugin uses as a quick-reject gate
# before running its 8 regexes. Mirrored here so file-mode matches the plugin
# exactly (same set as leaked_secret.check).
_LEAKED_SECRET_TOKENS = (
    "AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASCA",
    "sk-ant-", "sk-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
    "xox", "sk_live_", "rk_live_", "AIzaSy", "BEGIN ",
)


@dataclass
class Loc:
    file: str
    line: int

    def key(self) -> tuple[str, int]:
        return (self.file, self.line)


@dataclass
class RuleComparison:
    rule_id: str
    regex_hits: List[Loc] = field(default_factory=list)
    ast_hits: List[ShadowFinding] = field(default_factory=list)
    regex_redos_skipped: int = 0   # files whose regex noise-strip was bypassed (long-line guard)

    def regex_keys(self) -> set[tuple[str, int]]:
        return {l.key() for l in self.regex_hits}

    def ast_keys(self) -> set[tuple[str, int]]:
        return {(f.file, f.line) for f in self.ast_hits}

    def agree(self) -> set[tuple[str, int]]:
        return self.regex_keys() & self.ast_keys()

    def regex_only(self) -> set[tuple[str, int]]:
        return self.regex_keys() - self.ast_keys()

    def ast_only(self) -> set[tuple[str, int]]:
        return self.ast_keys() - self.regex_keys()


def iter_python_files(roots: Iterable[Path]) -> Iterable[Path]:
    """Bounded walk for *.py under each root, skipping vendor/venv/build trees.
    Deduplicates across overlapping roots."""
    seen: set[Path] = set()
    for root in roots:
        if not root.exists():
            continue
        if root.is_file():
            if root.suffix == ".py" and root not in seen:
                seen.add(root)
                yield root
            continue
        # os.walk with in-place dir pruning so we never descend into
        # node_modules/.git/venv trees (rglob would walk them all first).
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _EXCLUDE_PARTS]
            for fn in filenames:
                if not fn.endswith(".py"):
                    continue
                p = Path(dirpath) / fn
                if p in seen:
                    continue
                try:
                    if p.stat().st_size > MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                seen.add(p)
                yield p


def _regex_hits_for_repo(
    plugin_file: str, repo_root: Path, rule_id: str
) -> List[Loc]:
    """Run one regex plugin over a git-repo root and collect (file, line)."""
    rule = load_plugin_rule(_PLUGINS_DIR / plugin_file)
    ctx = RepoContext(repo_root=repo_root, mode=ScanMode.REPO)
    hits: List[Loc] = []
    for v in rule.check(ctx):
        if v.rule_id != rule_id or v.file is None or v.line is None:
            continue
        hits.append(Loc(file=v.file.replace("\\", "/"), line=v.line))
    return hits


def _regex_hits_per_file(source: str, rel: str) -> tuple[dict[str, List[Loc]], bool]:
    """Apply each plugin's OWN public regex machinery to one file's source.

    This mirrors the plugin `check()` line-matching exactly (same regexes,
    same noise-stripping, same safe-context shield) so file-mode numbers line
    up with repo-mode. Validated against the faithful `compare_on_repo` path
    in the measurement script."""
    from sentinel.rules.plugins import (
        insecure_deserialization as _ide,
        leaked_secret as _ls,
        unsafe_eval_exec as _uee,
    )
    from sentinel.io.skip_marker import line_is_suppressed

    out: dict[str, List[Loc]] = {rid: [] for rid in RULES}
    lines = source.splitlines()
    redos_skipped = False
    long_line = any(len(l) > LONG_LINE_LIMIT for l in lines)

    # Same trigger-token early-outs the plugins use before the (potentially
    # slow) _strip_noise pass. Without these, file-mode both diverges from the
    # plugin AND runs the noise regex on files the plugin would skip — which
    # caused a 66s stall on a regex-heavy source (hmac_compare_eq.py). See the
    # report's ReDoS finding. The long-line guard bounds the residual case where
    # the trigger token IS present but the file is a minified blob.
    if "eval(" in source or "exec(" in source:
        if long_line:
            redos_skipped = True
        else:
            stripped = _uee._strip_noise(source)
            for m in _uee._CALL_RE.finditer(stripped):
                ln = _uee._line_of(source, m.start())
                cur = lines[ln - 1] if ln - 1 < len(lines) else ""
                prv = lines[ln - 2] if ln - 2 >= 0 else ""
                if line_is_suppressed(cur, prv, "P0-unsafe-eval-exec"):
                    continue
                out["P0-unsafe-eval-exec"].append(Loc(rel, ln))

    if "pickle" in source or "marshal" in source or "yaml.load" in source:
        if long_line:
            redos_skipped = True
        else:
            stripped_d = _ide._strip_noise(source)
            for rx in (_ide._PICKLE_RE, _ide._YAML_RE):
                for m in rx.finditer(stripped_d):
                    ln = _ide._line_of(source, m.start())
                    out["P1-insecure-deserialization"].append(Loc(rel, ln))

    for lineno, line in enumerate(lines, start=1):
        # Same quick-reject gate the plugin uses: skip the 8-regex pass unless
        # a credential prefix token is present. Faithful AND ~10x faster.
        if not any(token in line for token in _LEAKED_SECRET_TOKENS):
            continue
        for name, pat in _ls._PATTERNS:
            mm = pat.search(line)
            if not mm:
                continue
            w0 = max(0, mm.start() - 40)
            w1 = min(len(line), mm.end() + 40)
            if _ls.SAFE_CONTEXT_WORDS.search(line[w0:w1]):
                continue
            out["P1-leaked-secret"].append(Loc(rel, lineno))
    return out, redos_skipped


def compare_on_files(
    files: List[Path],
    label_root: Optional[Path] = None,
    honor_skip: bool = True,
    progress_every: int = 0,
) -> dict[str, RuleComparison]:
    """Run BOTH matchers file-by-file (no git needed) — used for the crafted
    fixtures and non-git corpus dirs. Honors `sentinel:skip-file` on BOTH sides
    so the regex and AST columns see the identical file set."""
    comps = {rid: RuleComparison(rule_id=rid) for rid in RULES}

    def _rel(p: Path) -> str:
        if label_root is not None:
            try:
                return p.relative_to(label_root).as_posix()
            except ValueError:
                pass
        return p.as_posix()

    for i, path in enumerate(files, 1):
        if progress_every and i % progress_every == 0:
            print(f"[shadow] {i}/{len(files)} files", file=sys.stderr, flush=True)
        if honor_skip and has_skip_marker(path):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = _rel(path)

        hits, redos_skipped = _regex_hits_per_file(source, rel)
        for rid, locs in hits.items():
            comps[rid].regex_hits.extend(locs)
        if redos_skipped:
            comps["P0-unsafe-eval-exec"].regex_redos_skipped += 1
            comps["P1-insecure-deserialization"].regex_redos_skipped += 1
        for rid, (_plugin, ast_fn) in RULES.items():
            for f in ast_fn(source, rel):
                comps[rid].ast_hits.append(f)

    return comps


def compare_on_repo(repo_root: Path) -> dict[str, RuleComparison]:
    """Faithful comparison on a git worktree: the regex column is the REAL
    plugin `check()` output (honoring skip markers, exclude dirs, git file
    set); the AST column runs over the same tracked *.py files (also honoring
    skip markers). This is the authoritative measurement path."""
    comps = {rid: RuleComparison(rule_id=rid) for rid in RULES}

    # regex: real plugin.check over the repo
    for rid, (plugin_file, _ast_fn) in RULES.items():
        comps[rid].regex_hits = _regex_hits_for_repo(plugin_file, repo_root, rid)

    # AST: same tracked *.py file set the plugins scan
    for path in iter_repo_files(repo_root, "*.py", PY_EXCLUDE_DIRS):
        if has_skip_marker(path):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            rel = path.relative_to(repo_root).as_posix()
        except ValueError:
            rel = path.as_posix()
        for rid, (_plugin, ast_fn) in RULES.items():
            for f in ast_fn(source, rel):
                comps[rid].ast_hits.append(f)

    return comps
