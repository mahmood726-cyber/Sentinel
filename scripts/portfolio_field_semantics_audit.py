"""Run P1-aact-field-semantics across every local repo and write a portfolio report.

Discovers git repos under the common code roots, runs the single rule on each, and
aggregates the WARNs (every place a footgun AACT field is used as a filter).
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.core import RepoContext, ScanMode
from sentinel.registry.plugin_loader import load_plugin_rule

PLUGIN = Path(__file__).resolve().parent.parent / "sentinel" / "rules" / "plugins" / "aact_field_semantics.py"
ROOTS = [Path(r) for r in ("F:/", "F:/Models", "F:/Projects", "C:/Projects", "C:/Models")]
SKIP = {"node_modules", ".git", "__pycache__", ".venv", "venv"}


def discover_repos() -> list[Path]:
    seen: set[Path] = set()
    repos: list[Path] = []
    for root in ROOTS:
        if not root.is_dir():
            continue
        # repos at root, and one level down (umbrella folders)
        for depth in (root.glob("*/.git"), root.glob("*/*/.git")):
            for g in depth:
                repo = g.parent.resolve()
                if repo in seen or any(p in SKIP for p in repo.parts):
                    continue
                seen.add(repo)
                repos.append(repo)
    return sorted(repos)


def main() -> int:
    rule = load_plugin_rule(PLUGIN)
    repos = discover_repos()
    rows = []
    scanned = 0
    for repo in repos:
        try:
            vs = rule.check(RepoContext(repo_root=repo, mode=ScanMode.REPO))
        except Exception as e:  # noqa: BLE001
            rows.append((repo.name, "ERROR", str(e)[:80], None))
            continue
        scanned += 1
        for v in vs:
            field = v.detail.split("'")[1] if "'" in v.detail else "?"
            rows.append((repo.name, f"{v.file}:{v.line}", field, v.detail))
    hits = [r for r in rows if r[1] not in ("ERROR",)]
    out = ["# Portfolio audit — P1-aact-field-semantics",
           f"_generated {datetime.now(timezone.utc).isoformat(timespec='seconds')} · "
           f"{scanned} repos scanned · {len(hits)} field-filter findings_\n"]
    if not hits:
        out.append("No footgun AACT field used as a filter anywhere (outside the skip-file'd registry).")
    else:
        by_repo: dict = {}
        for repo, loc, field, detail in hits:
            by_repo.setdefault(repo, []).append((loc, field))
        for repo in sorted(by_repo):
            out.append(f"## {repo}")
            for loc, field in by_repo[repo]:
                out.append(f"- `{field}` at {loc}")
            out.append("")
    report = "\n".join(out)
    dest = Path(__file__).resolve().parent.parent / "field_semantics_portfolio_report.md"
    dest.write_text(report, encoding="utf-8")
    print(f"scanned={scanned} findings={len(hits)} -> {dest}")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
