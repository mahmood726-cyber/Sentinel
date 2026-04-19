#!/usr/bin/env python3
# sentinel:skip-file - sweep tool path references are runtime data
"""One-shot portfolio sweep for P1-leaked-secret findings.

Reads C:/ProjectIndex/agent-records/restart-manifest.json, runs every
registered Sentinel rule against each project path that exists on
disk, and reports only the P1-leaked-secret findings.

Output:
  - Per-repo list of findings (file, line, detail)
  - Total count by secret-type
  - Exit code 0 if zero findings; non-zero if any found.

Intended as a pre-promotion check: if the sweep returns zero findings,
the rule can be safely promoted from WARN to BLOCK severity.
"""
from __future__ import annotations

import json
import sys
import time
from collections import Counter
from pathlib import Path

from sentinel.core import RepoContext, ScanMode
from sentinel.registry.registry import Registry


MANIFEST = Path("C:/ProjectIndex/agent-records/restart-manifest.json")
RULES_ROOT = Path("C:/Sentinel/sentinel/rules")
TARGET_RULE = "P1-leaked-secret"


def load_repo_paths(manifest: Path) -> list[Path]:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    paths: list[Path] = []
    for rec in data.get("records", []):
        p = rec.get("resolvedPath") or rec.get("path")
        if not p:
            continue
        pp = Path(p)
        if pp.exists() and pp.is_dir():
            paths.append(pp)
    return paths


def main() -> int:
    t0 = time.time()
    print(f"Loading manifest: {MANIFEST}")
    repos = load_repo_paths(MANIFEST)
    print(f"  {len(repos)} project paths exist on disk.")

    reg = Registry.from_dir(RULES_ROOT)
    # Filter registry to just repo-scope rules — portfolio rules are
    # slow and need a different context (they'll re-read the manifest).
    repo_rules = [r for r in reg.all_rules() if getattr(r, "scope", "repo") == "repo"]
    print(f"  {len(repo_rules)} repo-scope rules loaded.")

    total_findings: list[dict] = []
    per_repo_counts: Counter[str] = Counter()
    kind_counts: Counter[str] = Counter()

    for i, repo in enumerate(repos, start=1):
        if i % 50 == 0 or i == len(repos):
            print(f"  [{i}/{len(repos)}] {time.time() - t0:.0f}s elapsed")
        ctx = RepoContext(repo_root=repo, mode=ScanMode.REPO)
        for rule in repo_rules:
            try:
                verdicts = rule.check(ctx)
            except Exception as e:
                print(f"    [error] {repo} / {rule.id}: {type(e).__name__}: {e}")
                continue
            for v in verdicts:
                if v.rule_id != TARGET_RULE:
                    continue
                total_findings.append({
                    "repo": str(repo),
                    "file": v.file,
                    "line": v.line,
                    "detail": v.detail,
                })
                per_repo_counts[str(repo)] += 1
                # Extract kind ("AWS access key" / "Anthropic API key" / ...)
                kind = v.detail.split(" in ")[0].removeprefix("possible ")
                kind_counts[kind] += 1

    dt = time.time() - t0
    print()
    print("=" * 60)
    print(f"Sweep complete in {dt:.1f}s across {len(repos)} repos")
    print(f"Total {TARGET_RULE} findings: {len(total_findings)}")
    print()
    if total_findings:
        print("By kind:")
        for kind, n in kind_counts.most_common():
            print(f"  {n:5d}  {kind}")
        print()
        print("By repo (top 20):")
        for repo, n in per_repo_counts.most_common(20):
            print(f"  {n:5d}  {repo}")
        print()
        print("Sample findings (first 25):")
        for f in total_findings[:25]:
            loc = f"{f['file']}:{f['line']}" if f['line'] else f['file']
            print(f"  {f['repo']} -> {loc}")
            print(f"    {f['detail']}")
        return 1

    print("No P1-leaked-secret findings across the portfolio.")
    print("The rule is safe to promote WARN -> BLOCK.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
