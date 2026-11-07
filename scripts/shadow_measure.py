"""Shadow measurement: regex (shipped rules) vs AST (shadow matchers).

Runs BOTH matchers over a corpus and reports, per rule:
  - regex hit count, AST hit count
  - agreement (same file:line)
  - regex-only and AST-only disagreements (with samples for adjudication)

Two corpus modes:
  * git repos  -> compare_on_repo (regex = REAL plugin.check; faithful)
  * loose dirs -> compare_on_files (regex = per-file re-application of the
                  plugin's own regexes; validated against repo-mode)

Usage:
  python scripts/shadow_measure.py --json-out <path> [--md-out <path>]

Nothing here enforces anything — it is measurement only (benchmark ★3 shadow).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Make `sentinel` importable when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.shadow.runner import (  # noqa: E402
    RULES,
    RuleComparison,
    compare_on_files,
    compare_on_repo,
    iter_python_files,
)

# Repos/dirs the harness must NOT touch (frozen or owned by other lanes).
# Reading is non-mutating, but we exclude them to respect the freeze.
FROZEN = ("rapidmeta-staging", "rapidmeta-finerenone", "rct-extractor-v2")


def _is_frozen(p: Path) -> bool:
    return any(f in p.as_posix() for f in FROZEN)


def _merge(into: dict[str, RuleComparison], src: dict[str, RuleComparison]) -> None:
    for rid, comp in src.items():
        into[rid].regex_hits.extend(comp.regex_hits)
        into[rid].ast_hits.extend(comp.ast_hits)


def _find_git_repos(root: Path, max_depth: int = 3) -> list[Path]:
    repos: list[Path] = []
    root = root.resolve()
    base_depth = len(root.parts)
    for gitdir in root.rglob(".git"):
        if len(gitdir.parent.parts) - base_depth > max_depth:
            continue
        repo = gitdir.parent
        if _is_frozen(repo):
            continue
        repos.append(repo)
    return repos


def _sample(comp: RuleComparison, which: str, n: int = 25) -> list[dict]:
    detail_by_key = {(f.file, f.line): (f.detail, f.kind) for f in comp.ast_hits}
    out = []
    keys = sorted(getattr(comp, which)())
    for file, line in keys[:n]:
        entry = {"file": file, "line": line}
        if (file, line) in detail_by_key:
            entry["ast_detail"] = detail_by_key[(file, line)][0]
            entry["ast_kind"] = detail_by_key[(file, line)][1]
        out.append(entry)
    return out


def _summarize(comps: dict[str, RuleComparison]) -> dict:
    result = {}
    for rid, comp in comps.items():
        rk, ak = comp.regex_keys(), comp.ast_keys()
        result[rid] = {
            "regex_hits": len(rk),
            "ast_hits": len(ak),
            "agree": len(comp.agree()),
            "regex_only": len(comp.regex_only()),
            "ast_only": len(comp.ast_only()),
            "regex_redos_skipped": comp.regex_redos_skipped,
            "regex_only_sample": _sample(comp, "regex_only"),
            "ast_only_sample": _sample(comp, "ast_only"),
            "ast_only_kinds": _kind_counts(comp),
        }
    return result


def _kind_counts(comp: RuleComparison) -> dict[str, int]:
    ast_only = comp.ast_only()
    counts: dict[str, int] = {}
    for f in comp.ast_hits:
        if (f.file, f.line) in ast_only:
            counts[f.kind] = counts.get(f.kind, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def run(corpus_git: list[Path], corpus_files_roots: list[Path],
        fixture_root: Path) -> dict:
    combined = {rid: RuleComparison(rule_id=rid) for rid in RULES}

    # 1) faithful repo-mode
    repo_reports = {}
    for repo in corpus_git:
        try:
            comp = compare_on_repo(repo)
        except Exception as e:  # never let one repo abort the sweep
            repo_reports[str(repo)] = {"error": f"{type(e).__name__}: {e}"}
            continue
        _merge(combined, comp)
        repo_reports[repo.as_posix()] = {
            rid: {"regex": len(c.regex_keys()), "ast": len(c.ast_keys())}
            for rid, c in comp.items()
        }

    # 2) loose-file sweep (volume + wild evasions)
    loose_files = [
        p for p in iter_python_files(corpus_files_roots)
        if not _is_frozen(p)
    ]
    print(f"[shadow] loose sweep: {len(loose_files)} python files", flush=True)
    loose = compare_on_files(loose_files, progress_every=500)
    _merge(combined, loose)

    # 3) fixture ground-truth (adjudicable)
    fixture_files = sorted(fixture_root.glob("*.py"))
    fixtures = compare_on_files(fixture_files, label_root=fixture_root,
                               honor_skip=False)

    return {
        "corpus": {
            "git_repos": [r.as_posix() for r in corpus_git],
            "loose_python_files": len(loose_files),
            "fixture_files": [f.name for f in fixture_files],
        },
        "combined_git_plus_loose": _summarize(combined),
        "per_repo": repo_reports,
        "fixtures": _summarize(fixtures),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json-out", type=Path, required=True)
    ap.add_argument("--git-root", type=Path, action="append", default=[],
                    help="Root under which to auto-discover git repos (repeatable)")
    ap.add_argument("--files-root", type=Path, action="append", default=[],
                    help="Root for loose-file *.py sweep (repeatable)")
    ap.add_argument("--extra-repo", type=Path, action="append", default=[],
                    help="Explicit git repo to include (repeatable)")
    args = ap.parse_args(argv)

    sentinel_root = Path(__file__).resolve().parent.parent
    fixture_root = sentinel_root / "tests" / "fixtures" / "shadow_ast"

    git_repos: list[Path] = list(args.extra_repo)
    for root in args.git_root:
        git_repos.extend(_find_git_repos(root))
    # de-dup, drop frozen
    seen, uniq = set(), []
    for r in git_repos:
        rp = r.resolve()
        if rp in seen or _is_frozen(rp):
            continue
        seen.add(rp)
        uniq.append(rp)

    report = run(uniq, list(args.files_root), fixture_root)
    args.json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    # console summary
    c = report["combined_git_plus_loose"]
    print(f"corpus: {len(uniq)} git repos + "
          f"{report['corpus']['loose_python_files']} loose files")
    for rid, s in c.items():
        print(f"  {rid:<32} regex={s['regex_hits']:<5} ast={s['ast_hits']:<5} "
              f"agree={s['agree']:<5} regex_only={s['regex_only']:<4} "
              f"ast_only={s['ast_only']:<4} kinds={s['ast_only_kinds']}")
    print(f"wrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
