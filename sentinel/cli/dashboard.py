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
