#!/usr/bin/env python3
# sentinel:skip-file - runtime-config paths by necessity
"""Portfolio-wide `gitleaks git` history sweep.

Sentinel's `P1-leaked-secret` rule scans only CURRENTLY-TRACKED files.
If a secret was committed, then deleted, it survives in git history and
is a permanent leak. This script runs gitleaks against the full commit
graph of every repo in restart-manifest.json and aggregates findings.

Output:
  - JSON report at scripts/gitleaks_history_findings.json
  - Stdout summary: total findings, top rules, top repos

Runtime: ~4 parallel workers, 120s per-repo timeout. Estimate 10-20 min
for 467 repos.

Exit code: 0 if zero findings, 1 otherwise.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


MANIFEST = Path("C:/ProjectIndex/agent-records/restart-manifest.json")
OUTPUT = Path("C:/Sentinel/scripts/gitleaks_history_findings.json")
GITLEAKS = Path(
    "C:/Users/user/AppData/Local/Microsoft/WinGet/Packages/"
    "Gitleaks.Gitleaks_Microsoft.Winget.Source_8wekyb3d8bbwe/gitleaks.exe"
)
MAX_WORKERS = 4
PER_REPO_TIMEOUT = 120  # seconds


def load_repo_paths(manifest: Path) -> list[Path]:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    out: list[Path] = []
    for rec in data.get("records", []):
        p = rec.get("resolvedPath") or rec.get("path")
        if not p:
            continue
        pp = Path(p)
        if pp.exists() and (pp / ".git").exists():
            out.append(pp)
    return out


def scan_one(repo: Path) -> tuple[Path, str, list[dict]]:
    """Run gitleaks on one repo; return (repo, status, findings)."""
    try:
        result = subprocess.run(
            [
                str(GITLEAKS), "git",
                "--no-banner",
                "--report-format", "json",
                "--report-path", "-",  # stdout
                "--log-level", "error",
                str(repo),
            ],
            capture_output=True, text=True, timeout=PER_REPO_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return repo, "TIMEOUT", []
    except (OSError, subprocess.SubprocessError) as e:
        return repo, f"ERROR:{type(e).__name__}", []

    # gitleaks exits 1 when leaks are found, 0 when clean. Both emit
    # JSON on stdout.
    findings: list[dict] = []
    if result.stdout:
        try:
            parsed = json.loads(result.stdout)
            if isinstance(parsed, list):
                findings = parsed
        except json.JSONDecodeError:
            return repo, "BAD_JSON", []
    return repo, "OK", findings


def main() -> int:
    t0 = time.time()
    print(f"gitleaks binary: {GITLEAKS}")
    print(f"Loading manifest: {MANIFEST}")
    repos = load_repo_paths(MANIFEST)
    print(f"  {len(repos)} git-backed repos on disk")
    print(f"  workers={MAX_WORKERS} per-repo-timeout={PER_REPO_TIMEOUT}s")
    print()

    status_counts: Counter[str] = Counter()
    all_findings: list[dict] = []
    per_repo: dict[str, list[dict]] = {}
    per_status_repos: dict[str, list[str]] = {}
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_to_repo = {pool.submit(scan_one, r): r for r in repos}
        for fut in as_completed(future_to_repo):
            repo, status, findings = fut.result()
            completed += 1
            status_counts[status] += 1
            per_status_repos.setdefault(status, []).append(str(repo))
            if findings:
                per_repo[str(repo)] = findings
                for f in findings:
                    f["_repo"] = str(repo)
                    all_findings.append(f)
            if completed % 25 == 0 or completed == len(repos):
                elapsed = time.time() - t0
                rate = completed / max(elapsed, 1e-9)
                print(
                    f"  [{completed}/{len(repos)}] {elapsed:.0f}s elapsed "
                    f"({rate:.1f}/s) | findings={len(all_findings)}"
                )

    dt = time.time() - t0
    print()
    print("=" * 60)
    print(f"Gitleaks history sweep complete in {dt:.0f}s")
    print(f"Status: {dict(status_counts)}")
    print(f"Total findings: {len(all_findings)}")
    print()

    if all_findings:
        by_rule: Counter[str] = Counter()
        by_repo: Counter[str] = Counter()
        for f in all_findings:
            rule = f.get("RuleID") or f.get("Description") or "<unknown>"
            by_rule[rule] += 1
            by_repo[f["_repo"]] += 1
        print("By rule (top 20):")
        for rule, n in by_rule.most_common(20):
            print(f"  {n:5d}  {rule}")
        print()
        print("By repo (top 20):")
        for repo, n in by_repo.most_common(20):
            print(f"  {n:5d}  {repo}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps({
            "generated_at": time.time(),
            "runtime_seconds": dt,
            "status_counts": dict(status_counts),
            "per_status_repos": per_status_repos,
            "total_findings": len(all_findings),
            "per_repo": per_repo,
        }, indent=2),
        encoding="utf-8",
    )
    print(f"\nFull report: {OUTPUT}")
    return 1 if all_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
