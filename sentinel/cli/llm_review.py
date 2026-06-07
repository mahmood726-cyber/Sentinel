"""`sentinel llm-review` — agent-driven LLM discovery pass (WARN-only).

Sentinel is a DETERMINISTIC, fail-closed engine: it catches only what has been
encoded as a rule (high precision, zero novel-bug recall). This command adds a
complementary DISCOVERY pass WITHOUT touching that property. It does not call any
model itself — no network, no API key, no cost — it emits a structured review
packet that an agent already in the loop (Claude Code) processes, then ingests
the agent's findings as WARN-tier "candidate rules".

Two-step, agent-driven (chosen 2026-06-07 to preserve the offline/free ethos):

  1. emit:   sentinel llm-review --repo R
               -> writes .sentinel-llm-review-request.json
                  {diff, existing_rules, prompt, schema}
  2. (the agent reads that packet and returns findings JSON)
  3. ingest: sentinel llm-review --repo R --ingest findings.json
               -> appends [WARN] LLM-candidate:<slug> to sentinel-findings.{jsonl,md}

Invariants (by design, not configurable):
  - WARN ONLY, never BLOCK. LLM findings are probabilistic; a fail-closed push
    gate must stay deterministic.
  - NOT wired into the pre-push hook. Discovery is opt-in, off the hot path.
  - Findings are tagged LLM-candidate so a human can promote a confirmed one to
    a real deterministic rule — closing the incident->rule loop with discovery.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from sentinel.core.severity import Severity
from sentinel.core.verdict import Verdict
from sentinel.io.writer import write_findings

REQUEST_FILE = ".sentinel-llm-review-request.json"
_DIFF_CAP = 200_000  # chars; bound the packet so a huge diff can't blow it up
_SOURCE = "llm-review (agent-driven candidate, not a deterministic rule)"


def _sentinel_repo_root() -> Path:
    return Path(__file__).parent.parent.parent


def _collect_diff(repo: Path, base: str | None) -> tuple[str, str]:
    """Unified diff for the changes under review. Tries upstream, then HEAD.
    Fails soft (returns empty) — never raises into the CLI."""
    refs = [base] if base else ["@{u}", "HEAD"]
    for ref in refs:
        try:
            r = subprocess.run(
                ["git", "-C", str(repo), "diff", ref],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout, ref
        except (subprocess.SubprocessError, OSError):
            continue
    return "", refs[-1]


def _existing_rule_ids(manifest_path: Path) -> list[str]:
    """Rule identifiers Sentinel already enforces, so the agent does not
    re-report them. Robust to manifest shape (dict-of-rules or list)."""
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    rules = data.get("rules", data) if isinstance(data, dict) else data
    ids: list[str] = []
    if isinstance(rules, dict):
        for k, v in rules.items():
            ids.append(str(v.get("id", k)) if isinstance(v, dict) else str(k))
    elif isinstance(rules, list):
        for v in rules:
            if isinstance(v, dict) and (v.get("id") or v.get("rule_id")):
                ids.append(str(v.get("id") or v.get("rule_id")))
    return sorted(set(ids))


_REVIEW_PROMPT = (
    "You are a code reviewer feeding Sentinel, a deterministic pre-push rule "
    "engine. Review ONLY the unified diff below for NOVEL correctness, security, "
    "or data-integrity bugs that the existing Sentinel rules (listed) do NOT "
    "already cover. Do not restate style nits or anything an existing rule would "
    "catch. Prefer few high-confidence findings over many speculative ones; if "
    "unsure, omit it. For each finding return an object matching the schema. "
    "These become WARN-tier 'candidate rules' for human review, never an "
    "automatic block."
)

_FINDINGS_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "required": ["title", "detail"],
        "properties": {
            "file": {"type": "string"},
            "line": {"type": "integer"},
            "title": {"type": "string", "description": "short kebab-case-able label"},
            "detail": {"type": "string"},
            "fix_hint": {"type": "string"},
        },
    },
}


def _emit(repo: Path, base: str | None) -> int:
    diff, ref = _collect_diff(repo, base)
    if not diff.strip():
        print(f"[llm-review] no diff under review (ref={ref}); nothing to do.")
        return 0
    truncated = len(diff) > _DIFF_CAP
    if truncated:
        diff = diff[:_DIFF_CAP]
    packet = {
        "_schema": "sentinel-llm-review-request-v1",
        "repo": str(repo),
        "diff_ref": ref,
        "diff_truncated": truncated,  # surfaced, never silent (lessons.md)
        "existing_rules": _existing_rule_ids(_sentinel_repo_root() / "rules-manifest.json"),
        "prompt": _REVIEW_PROMPT,
        "findings_schema": _FINDINGS_SCHEMA,
        "diff": diff,
    }
    out = repo / REQUEST_FILE
    out.write_text(json.dumps(packet, indent=2, ensure_ascii=False), encoding="utf-8")
    if truncated:
        print(f"[llm-review] WARNING: diff exceeded {_DIFF_CAP} chars and was truncated.")
    print(f"[llm-review] wrote {out}")
    print("  Next: have Claude Code read that packet, produce findings JSON")
    print("  matching findings_schema, then run:")
    print(f"    sentinel llm-review --repo {repo} --ingest <findings.json>")
    return 0


def _slug(title: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(title).lower()).strip("-")
    return (s or "finding")[:48]


def _ingest(repo: Path, findings_path: Path) -> int:
    try:
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"[llm-review] cannot read findings: {e}", file=sys.stderr)
        return 2
    if isinstance(findings, dict) and "findings" in findings:
        findings = findings["findings"]
    if not isinstance(findings, list):
        print("[llm-review] findings JSON must be a list (or {findings:[...]})", file=sys.stderr)
        return 2
    now = datetime.now(timezone.utc)
    repo_name = repo.name
    verdicts: list[Verdict] = []
    skipped = 0
    for f in findings:
        if not isinstance(f, dict) or not f.get("title") or not f.get("detail"):
            skipped += 1  # require the two mandatory fields; never fabricate them
            continue
        line = f.get("line")
        verdicts.append(Verdict(
            rule_id=f"LLM-candidate:{_slug(f['title'])}",
            severity=Severity.WARN,
            repo=repo_name,
            file=(str(f["file"]) if f.get("file") else None),
            line=(int(line) if isinstance(line, int) else None),
            detail=str(f["detail"]),
            fix_hint=str(f.get("fix_hint", "Review; if real, promote to a deterministic Sentinel rule.")),
            source=_SOURCE,
            timestamp=now,
        ))
    if verdicts:
        write_findings(repo, verdicts)
    print(f"[llm-review] ingested {len(verdicts)} WARN candidate finding(s)"
          + (f"; skipped {skipped} malformed" if skipped else "")
          + ". These are advisory — none block. Promote confirmed ones to real rules.")
    return 0


def _run(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        print(f"[llm-review] repo not found: {repo}", file=sys.stderr)
        return 2
    if args.ingest:
        return _ingest(repo, Path(args.ingest))
    return _emit(repo, args.base)


def add_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "llm-review",
        help="Agent-driven LLM discovery pass (WARN-only candidate rules, never blocks)",
    )
    p.add_argument("--repo", required=True, help="path to the repo under review")
    p.add_argument("--base", default=None,
                   help="git ref to diff against (default: upstream @{u}, then HEAD)")
    p.add_argument("--ingest", default=None, metavar="FINDINGS_JSON",
                   help="ingest an agent's findings JSON as WARN candidate rules")
    p.set_defaults(func=_run)
