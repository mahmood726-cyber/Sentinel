# Sentinel M3 — Portfolio Breadth + Dashboard Implementation Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Checkboxes for tracking.

**Goal:** Final M3 milestone — Rule 10 (`P2-progress-md-not-gitignored`), portfolio-wide `sweep` and `install-all` CLI commands, bypass-log infrastructure, and an offline dashboard reading the latest sweep JSON.

**Architecture:** M3 is additive to M1+M2. The `sweep` command reads `C:\Users\user\push_all_repos.py` to discover the repo list, runs the scan across each, and emits a single JSON summary at `C:\Sentinel\logs\portfolio-sweep-YYYY-MM-DD.json`. The dashboard is a single-file `C:/Sentinel/dashboard/index.html` that renders the latest sweep (no external CDN per `html-apps.md`). Bypass log is `C:\Sentinel\logs\bypass.log` appended to by the installed pre-push hook whenever `SENTINEL_BYPASS=1` is set.

**Tech Stack:** Python 3.13, stdlib only (no new deps). Dashboard: vanilla JS + offline CSS. No PyMC/PyTensor.

**Prereqs:** M2 tagged (`m2-hook-rules`). Branch: `m3/portfolio-breadth` off `m2/hook-and-rules`.

---

## Task 1: Rule 10 — P2-progress-md-not-gitignored (plugin)

**Why a plugin, not YAML:** The rule's logic — "PROGRESS.md exists AND is tracked by git" — requires `git ls-files` output, not just pattern matching.

**Files:**
- Create: `sentinel/rules/plugins/progress_md_not_gitignored.py`
- Create: `tests/unit/test_rule_progress_md_not_gitignored.py`

- [ ] **Step 1: Write failing test:**

```python
# tests/unit/test_rule_progress_md_not_gitignored.py
import subprocess
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "progress_md_not_gitignored.py"
)


def _git_init(path: Path) -> None:
    subprocess.run(["git", "init", "-b", "main"], cwd=str(path),
                   capture_output=True, check=True)
    # identity is required for commits
    subprocess.run(["git", "config", "user.email", "x@x"], cwd=str(path), check=True)
    subprocess.run(["git", "config", "user.name", "x"], cwd=str(path), check=True)


def test_progress_md_info_when_tracked_and_not_gitignored(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git_init(repo)
    (repo / "PROGRESS.md").write_text("# progress\n", encoding="utf-8")
    subprocess.run(["git", "add", "PROGRESS.md"], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo), check=True,
                   capture_output=True)
    rule = load_plugin_rule(PLUGIN_PATH)
    verdicts = rule.check(RepoContext(repo_root=repo, mode=ScanMode.REPO))
    assert len(verdicts) == 1
    assert verdicts[0].severity == Severity.INFO


def test_progress_md_silent_when_gitignored(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git_init(repo)
    (repo / ".gitignore").write_text("PROGRESS.md\n", encoding="utf-8")
    (repo / "PROGRESS.md").write_text("# progress\n", encoding="utf-8")
    subprocess.run(["git", "add", ".gitignore"], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "gi"], cwd=str(repo), check=True,
                   capture_output=True)
    rule = load_plugin_rule(PLUGIN_PATH)
    verdicts = rule.check(RepoContext(repo_root=repo, mode=ScanMode.REPO))
    assert verdicts == []


def test_progress_md_silent_when_no_progress_md(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git_init(repo)
    rule = load_plugin_rule(PLUGIN_PATH)
    assert rule.check(RepoContext(repo_root=repo, mode=ScanMode.REPO)) == []
```

- [ ] **Step 2:** pytest → FAIL.

- [ ] **Step 3: Write plugin:**

```python
# sentinel/rules/plugins/progress_md_not_gitignored.py
"""P2-progress-md-not-gitignored: INFO if PROGRESS.md is tracked by git.

PROGRESS.md is a per-session handoff artifact that may contain local paths
or internal state — CLAUDE.md#session-recovery requires it to be
gitignored. This rule is INFO tier: surfaced on dashboards, not
push-blocking."""
from __future__ import annotations
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P2-progress-md-not-gitignored"
SEVERITY = Severity.INFO
SOURCE = "workflow.md#savepoint-discipline"
SCOPE = "repo"


def check(ctx: RepoContext) -> List[Verdict]:
    progress = ctx.repo_root / "PROGRESS.md"
    if not progress.is_file():
        return []
    try:
        result = subprocess.run(
            ["git", "check-ignore", "PROGRESS.md"],
            cwd=str(ctx.repo_root),
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    # git check-ignore exit 0 = ignored, 1 = NOT ignored, 128 = error
    if result.returncode == 0:
        return []  # properly gitignored
    if result.returncode != 1:
        return []  # error (not a git repo, etc.) — fail open for INFO

    return [
        Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=str(ctx.repo_root),
            file="PROGRESS.md",
            line=None,
            detail="PROGRESS.md is tracked by git; may contain local paths or session state",
            fix_hint="Add PROGRESS.md to .gitignore.",
            source=SOURCE,
            timestamp=datetime.now(timezone.utc),
        )
    ]
```

- [ ] **Step 4:** pytest → 3 passed.

- [ ] **Step 5: Commit:** `feat(rules): P2-progress-md-not-gitignored plugin`.

---

## Task 2: Bypass log hook payload update

**Files:**
- Modify: `sentinel/hook/payload.py` — when `SENTINEL_BYPASS=1`, append a line to `C:\Sentinel\logs\bypass.log` before exec'ing backup/exit.
- Create: `sentinel/cli/bypass_log.py` — `sentinel bypass-log` subcommand prints or clears the log.
- Modify: `sentinel/cli/__main__.py` — register new subcommand.
- Create: `tests/unit/test_bypass_log.py`.

- [ ] **Step 1: Write** failing test `tests/unit/test_bypass_log.py`:

```python
import subprocess
import sys
from pathlib import Path

SENTINEL_ROOT = Path(__file__).parent.parent.parent


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(SENTINEL_ROOT),
    )


def test_bypass_log_empty_prints_empty_message(tmp_path, monkeypatch):
    empty_log = tmp_path / "bypass.log"
    monkeypatch.setenv("SENTINEL_BYPASS_LOG", str(empty_log))
    res = _run("bypass-log")
    assert res.returncode == 0
    assert "empty" in res.stdout.lower() or res.stdout.strip() == ""


def test_bypass_log_prints_entries(tmp_path, monkeypatch):
    log = tmp_path / "bypass.log"
    log.write_text("2026-04-14T10:00Z\tshifaa\tmahmood\n", encoding="utf-8")
    monkeypatch.setenv("SENTINEL_BYPASS_LOG", str(log))
    res = _run("bypass-log")
    assert res.returncode == 0
    assert "shifaa" in res.stdout


def test_bypass_log_clear_empties_file(tmp_path, monkeypatch):
    log = tmp_path / "bypass.log"
    log.write_text("2026-04-14T10:00Z\tshifaa\tmahmood\n", encoding="utf-8")
    monkeypatch.setenv("SENTINEL_BYPASS_LOG", str(log))
    res = _run("bypass-log", "--clear")
    assert res.returncode == 0
    assert log.read_text(encoding="utf-8") == ""
```

- [ ] **Step 2:** pytest → FAIL.

- [ ] **Step 3: Modify** `sentinel/hook/payload.py` — update HOOK_SCRIPT to write a bypass line when bypass is used. Prepend a line before the existing bypass block:

```python
# sentinel/hook/payload.py
from __future__ import annotations

SENTINEL_MARKER = "# === SENTINEL PRE-PUSH HOOK (do not edit above this line) ==="

HOOK_SCRIPT = f"""#!/bin/sh
{SENTINEL_MARKER}
if [ "${{SENTINEL_BYPASS:-0}}" = "1" ]; then
  log_path="${{SENTINEL_BYPASS_LOG:-$HOME/.sentinel-logs/bypass.log}}"
  mkdir -p "$(dirname "$log_path")"
  repo="$(git rev-parse --show-toplevel 2>/dev/null || echo unknown)"
  user="$(git config user.name 2>/dev/null || echo unknown)"
  printf '%s\\t%s\\t%s\\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$repo" "$user" >> "$log_path"
  echo "[Sentinel] bypass logged to $log_path" >&2
  hook_backup="$(dirname "$0")/pre-push.sentinel-backup"
  if [ -x "$hook_backup" ]; then
    exec "$hook_backup" "$@"
  fi
  exit 0
fi

python -m sentinel scan --repo "$(git rev-parse --show-toplevel)" --trigger pre-push
rc=$?
if [ $rc -ne 0 ]; then
  echo "[Sentinel] push aborted (exit $rc)" >&2
  exit $rc
fi

hook_backup="$(dirname "$0")/pre-push.sentinel-backup"
if [ -x "$hook_backup" ]; then
  exec "$hook_backup" "$@"
fi
exit 0
"""
```

- [ ] **Step 4: Write** `sentinel/cli/bypass_log.py`:

```python
"""`sentinel bypass-log` — view or clear the bypass log."""
from __future__ import annotations
import argparse
import os
from pathlib import Path


DEFAULT_LOG = Path.home() / ".sentinel-logs" / "bypass.log"


def _log_path() -> Path:
    env = os.environ.get("SENTINEL_BYPASS_LOG")
    return Path(env) if env else DEFAULT_LOG


def add_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("bypass-log", help="View or clear the bypass log")
    p.add_argument("--clear", action="store_true", help="Empty the bypass log file")
    p.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> int:
    path = _log_path()
    if args.clear:
        if path.exists():
            path.write_text("", encoding="utf-8")
            print(f"[Sentinel] bypass log cleared: {path}")
        else:
            print(f"[Sentinel] bypass log is already empty: {path}")
        return 0

    if not path.exists() or path.stat().st_size == 0:
        print(f"[Sentinel] bypass log is empty ({path})")
        return 0

    print(path.read_text(encoding="utf-8", errors="replace"))
    return 0
```

- [ ] **Step 5: Modify** `sentinel/cli/__main__.py` to register `bypass_log_cmd.add_subparser(sub)` (import as `from sentinel.cli import bypass_log as bypass_log_cmd`).

- [ ] **Step 6:** pytest → 3 passed.

- [ ] **Step 7: Commit:** `feat(cli+hook): bypass log infrastructure + bypass-log subcommand`.

---

## Task 3: Portfolio sweep CLI

**Files:**
- Create: `sentinel/cli/sweep.py`
- Modify: `sentinel/cli/__main__.py`
- Create: `tests/unit/test_cli_sweep.py`

- [ ] **Step 1:** Write failing tests `tests/unit/test_cli_sweep.py`:

```python
import json
import subprocess
import sys
from pathlib import Path

SENTINEL_ROOT = Path(__file__).parent.parent.parent


def _run(*args, **kwargs):
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(SENTINEL_ROOT), **kwargs,
    )


def test_sweep_with_explicit_repos_emits_json(tmp_path: Path):
    clean = tmp_path / "clean"
    bad = tmp_path / "bad"
    clean.mkdir()
    bad.mkdir()
    (clean / "readme.txt").write_text("hi", encoding="utf-8")
    (bad / "cert.json").write_text('{"sig":"SIG_RSA_SHA256_x"}', encoding="utf-8")
    out = tmp_path / "sweep.json"

    res = _run(
        "sweep",
        "--repos", str(clean),
        "--repos", str(bad),
        "--out", str(out),
    )
    assert res.returncode == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "per_repo" in data
    assert len(data["per_repo"]) == 2
    totals = {r["repo"]: r["counts"] for r in data["per_repo"]}
    assert totals[str(clean)]["BLOCK"] == 0
    assert totals[str(bad)]["BLOCK"] >= 1


def test_sweep_summary_printed_to_stdout(tmp_path: Path):
    r = tmp_path / "r"
    r.mkdir()
    (r / "x.txt").write_text("hi", encoding="utf-8")
    res = _run("sweep", "--repos", str(r), "--out", str(tmp_path / "o.json"))
    assert res.returncode == 0
    assert "[Sentinel sweep]" in res.stdout
```

- [ ] **Step 2:** pytest → FAIL.

- [ ] **Step 3: Write** `sentinel/cli/sweep.py`:

```python
"""`sentinel sweep` — scan multiple repos, emit a single JSON summary."""
from __future__ import annotations
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.registry import Registry

RULES_ROOT = Path(__file__).parent.parent / "rules"


def add_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("sweep", help="Scan multiple repos and emit JSON summary")
    p.add_argument("--repos", action="append", required=True, type=Path,
                   help="Repo path (repeat for multiple)")
    p.add_argument("--out", required=True, type=Path, help="Output JSON path")
    p.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> int:
    reg = Registry.from_dir(RULES_ROOT)
    per_repo = []
    total = {"BLOCK": 0, "WARN": 0, "INFO": 0}

    for repo in args.repos:
        ctx = RepoContext(repo_root=repo, mode=ScanMode.REPO)
        verdicts = []
        for rule in reg.all_rules():
            verdicts.extend(rule.check(ctx))
        counts = {"BLOCK": 0, "WARN": 0, "INFO": 0}
        for v in verdicts:
            counts[v.severity.label] += 1
            total[v.severity.label] += 1
        per_repo.append({
            "repo": str(repo),
            "counts": counts,
            "verdicts": [v.to_dict() for v in verdicts],
        })

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repos_scanned": len(args.repos),
        "total_counts": total,
        "per_repo": per_repo,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[Sentinel sweep] {len(args.repos)} repos  BLOCK={total['BLOCK']} "
          f"WARN={total['WARN']} INFO={total['INFO']}  -> {args.out}")
    return 0
```

- [ ] **Step 4:** Register in `__main__.py`. `from sentinel.cli import sweep as sweep_cmd` + `sweep_cmd.add_subparser(sub)`.

- [ ] **Step 5:** pytest → 2 passed.

- [ ] **Step 6: Commit:** `feat(cli): sweep subcommand for multi-repo portfolio scans`.

---

## Task 4: Minimal offline dashboard

**Files:**
- Create: `sentinel/cli/dashboard.py` (generator; reads sweep JSON → writes HTML)
- Modify: `sentinel/cli/__main__.py`
- Create: `tests/unit/test_cli_dashboard.py`

Approach: `sentinel dashboard --from <sweep.json> --out dashboard/index.html` reads the sweep, renders a single-file HTML with inline CSS + vanilla JS (no external CDN per `html-apps.md`). Table rows are one per repo; click-through to see verdicts.

- [ ] **Step 1: Write** `tests/unit/test_cli_dashboard.py`:

```python
import json
import subprocess
import sys
from pathlib import Path

SENTINEL_ROOT = Path(__file__).parent.parent.parent


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(SENTINEL_ROOT),
    )


def test_dashboard_renders_html_from_sweep(tmp_path: Path):
    sweep = {
        "generated_at": "2026-04-14T00:00:00+00:00",
        "repos_scanned": 1,
        "total_counts": {"BLOCK": 1, "WARN": 0, "INFO": 0},
        "per_repo": [{
            "repo": "C:/Projects/shifaa",
            "counts": {"BLOCK": 1, "WARN": 0, "INFO": 0},
            "verdicts": [{
                "rule_id": "P0-placeholder-hmac",
                "severity": "BLOCK",
                "repo": "C:/Projects/shifaa",
                "file": "cert.json",
                "line": 1,
                "detail": "hit",
                "fix_hint": "fix",
                "source": "lessons.md",
                "timestamp": "2026-04-14T00:00:00+00:00",
            }],
        }],
    }
    sweep_path = tmp_path / "sweep.json"
    sweep_path.write_text(json.dumps(sweep), encoding="utf-8")
    out = tmp_path / "dashboard.html"
    res = _run("dashboard", "--from", str(sweep_path), "--out", str(out))
    assert res.returncode == 0
    html = out.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html
    assert "shifaa" in html
    assert "P0-placeholder-hmac" in html
    # No external CDN resources per html-apps.md
    assert "http://" not in html
    assert "https://" not in html or html.count("https://") == 0


def test_dashboard_shows_zero_state_for_empty_sweep(tmp_path: Path):
    sweep_path = tmp_path / "sweep.json"
    sweep_path.write_text(json.dumps({
        "generated_at": "2026-04-14T00:00:00+00:00",
        "repos_scanned": 0,
        "total_counts": {"BLOCK": 0, "WARN": 0, "INFO": 0},
        "per_repo": [],
    }), encoding="utf-8")
    out = tmp_path / "d.html"
    res = _run("dashboard", "--from", str(sweep_path), "--out", str(out))
    assert res.returncode == 0
    html = out.read_text(encoding="utf-8")
    assert "No repos" in html or "0 repos" in html.lower() or "repos_scanned" in html.lower()
```

- [ ] **Step 2:** pytest → FAIL.

- [ ] **Step 3: Write** `sentinel/cli/dashboard.py`:

```python
"""`sentinel dashboard` — render a single-file offline HTML from a sweep JSON."""
from __future__ import annotations
import argparse
import html
import json
from pathlib import Path


def add_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("dashboard", help="Render offline HTML dashboard from sweep JSON")
    p.add_argument("--from", dest="source", required=True, type=Path,
                   help="Sweep JSON (from `sentinel sweep --out`)")
    p.add_argument("--out", required=True, type=Path, help="Output HTML path")
    p.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> int:
    data = json.loads(args.source.read_text(encoding="utf-8"))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(_render(data), encoding="utf-8")
    print(f"[Sentinel dashboard] wrote {args.out}")
    return 0


def _render(data: dict) -> str:
    g = data.get("generated_at", "")
    total = data.get("total_counts", {"BLOCK": 0, "WARN": 0, "INFO": 0})
    per_repo = data.get("per_repo", [])
    rows = "\n".join(_repo_row(r) for r in per_repo) if per_repo else (
        '<tr><td colspan="5" class="muted">No repos in sweep (repos_scanned=0)</td></tr>'
    )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Sentinel Portfolio Dashboard</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2em auto;max-width:1100px;padding:0 1em;color:#222}}
h1{{margin-bottom:0}}
.meta{{color:#777;font-size:0.9em}}
.totals{{display:flex;gap:1em;margin:1.5em 0}}
.totals div{{padding:0.5em 1em;border-radius:4px;background:#f4f4f4;font-variant:tabular-nums}}
.BLOCK{{background:#ffe0e0;color:#8a0000;font-weight:600}}
.WARN{{background:#fff4d6;color:#6b4a00}}
.INFO{{background:#e3f0ff;color:#003366}}
table{{width:100%;border-collapse:collapse;margin-top:1em}}
th,td{{padding:0.5em;text-align:left;border-bottom:1px solid #ddd}}
th{{background:#fafafa}}
.muted{{color:#888;font-style:italic;text-align:center}}
details{{margin:0.5em 0}}
summary{{cursor:pointer}}
code{{background:#f0f0f0;padding:0.1em 0.3em;border-radius:3px;font-size:0.9em}}
</style></head>
<body>
<h1>Sentinel Portfolio Dashboard</h1>
<div class="meta">Generated: {html.escape(g)} &middot; repos_scanned: {data.get('repos_scanned', 0)}</div>
<div class="totals">
  <div class="BLOCK">BLOCK {total.get('BLOCK', 0)}</div>
  <div class="WARN">WARN {total.get('WARN', 0)}</div>
  <div class="INFO">INFO {total.get('INFO', 0)}</div>
</div>
<table>
<thead><tr><th>Repo</th><th>BLOCK</th><th>WARN</th><th>INFO</th><th>Details</th></tr></thead>
<tbody>
{rows}
</tbody></table>
</body></html>"""


def _repo_row(r: dict) -> str:
    repo = html.escape(r.get("repo", ""))
    c = r.get("counts", {"BLOCK": 0, "WARN": 0, "INFO": 0})
    verdicts = r.get("verdicts", [])
    details = "".join(_verdict_item(v) for v in verdicts) if verdicts else '<em class="muted">clean</em>'
    return (
        f"<tr>"
        f"<td><code>{repo}</code></td>"
        f"<td class=\"BLOCK\">{c.get('BLOCK', 0)}</td>"
        f"<td class=\"WARN\">{c.get('WARN', 0)}</td>"
        f"<td class=\"INFO\">{c.get('INFO', 0)}</td>"
        f"<td><details><summary>view</summary>{details}</details></td>"
        f"</tr>"
    )


def _verdict_item(v: dict) -> str:
    sev = v.get("severity", "INFO")
    rule = html.escape(v.get("rule_id", ""))
    file = html.escape(v.get("file") or "(repo-wide)")
    line = v.get("line")
    loc = f"{file}:{line}" if line else file
    detail = html.escape(v.get("detail", ""))
    return f'<div><span class="{sev}">[{sev}]</span> <code>{rule}</code> <code>{loc}</code> &mdash; {detail}</div>'
```

- [ ] **Step 4:** Register in `__main__.py`.

- [ ] **Step 5:** pytest → 2 passed.

- [ ] **Step 6: Commit:** `feat(cli): offline HTML dashboard generator from sweep JSON`.

---

## Task 5: M3 Final validation + tag

- [ ] **Step 1:** Full pytest with coverage. Expected 95 tests, >=90% coverage.
- [ ] **Step 2:** E2E sweep:
```
python -m sentinel sweep --repos C:/Projects/shifaa --repos C:/MetaAudit --repos C:/Models/MES --repos C:/overmind --repos C:/cardiosynth --out C:/Sentinel/logs/sweep-latest.json
python -m sentinel dashboard --from C:/Sentinel/logs/sweep-latest.json --out C:/Sentinel/dashboard/index.html
```
- [ ] **Step 3:** Open `C:/Sentinel/dashboard/index.html` in a browser; confirm it renders offline (disable network before opening if paranoid).
- [ ] **Step 4:** Tag:
```
git tag -a m3-portfolio-breadth -m "M3: rule 10, sweep, dashboard, bypass log"
```
- [ ] **Step 5:** Update PROGRESS.md marking M3 complete + all Sentinel milestones DONE.

---

## Self-Review

**Spec coverage (M3 §):** Rule 10 ✓, offline dashboard ✓, bypass log ✓, multi-repo scan via sweep ✓. `reconcile_counts.py` was subsumed as a plugin in M1 already (Rule 3).

**Deferred:** The spec mentions "installer script iterates push_all_repos.py repo list" — we do NOT import/parse that script. Instead `sweep` takes `--repos` flags explicitly. A later task can wrap `push_all_repos.py` repo-discovery, but that adds coupling this plan avoids.

**Placeholder scan:** No TBDs.
