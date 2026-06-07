"""Tests for `sentinel llm-review` — agent-driven WARN-only discovery pass."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from sentinel.cli import llm_review as lr
from sentinel.io.paths import WARN_JSONL, BLOCK_JSONL


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True, text=True)


def _repo_with_change(tmp_path: Path) -> Path:
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t.t")
    _git(repo, "config", "user.name", "t")
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    (repo / "a.py").write_text("x = 1 / 0\n", encoding="utf-8")  # a change to diff
    return repo


def test_emit_writes_packet(tmp_path):
    repo = _repo_with_change(tmp_path)
    rc = lr._run(_ns(repo=str(repo), base="HEAD", ingest=None))
    assert rc == 0
    packet = json.loads((repo / lr.REQUEST_FILE).read_text(encoding="utf-8"))
    assert packet["_schema"] == "sentinel-llm-review-request-v1"
    assert "diff" in packet and "a.py" in packet["diff"]
    assert isinstance(packet["existing_rules"], list)
    assert packet["findings_schema"]["type"] == "array"


def test_ingest_writes_warn_not_block(tmp_path):
    repo = _repo_with_change(tmp_path)
    findings = [
        {"file": "a.py", "line": 1, "title": "Division by zero",
         "detail": "1/0 raises ZeroDivisionError", "fix_hint": "guard denominator"},
        {"title": "no-file finding", "detail": "repo-wide concern"},
    ]
    fp = repo / "f.json"
    fp.write_text(json.dumps(findings), encoding="utf-8")
    rc = lr._run(_ns(repo=str(repo), base=None, ingest=str(fp)))
    assert rc == 0
    # WARN channel has both; BLOCK channel untouched.
    warn_lines = (repo / WARN_JSONL).read_text(encoding="utf-8").strip().splitlines()
    assert len(warn_lines) == 2
    recs = [json.loads(x) for x in warn_lines]
    assert all(r["severity"] == "WARN" for r in recs)
    assert all(r["rule_id"].startswith("LLM-candidate:") for r in recs)
    assert recs[0]["rule_id"] == "LLM-candidate:division-by-zero"
    assert not (repo / BLOCK_JSONL).exists()


def test_ingest_skips_malformed_findings(tmp_path):
    repo = _repo_with_change(tmp_path)
    findings = [
        {"title": "ok", "detail": "real"},
        {"title": "missing detail"},          # no detail -> skip
        {"detail": "missing title"},           # no title -> skip
        "not-an-object",                        # skip
    ]
    fp = repo / "f.json"
    fp.write_text(json.dumps(findings), encoding="utf-8")
    rc = lr._run(_ns(repo=str(repo), base=None, ingest=str(fp)))
    assert rc == 0
    warn_lines = (repo / WARN_JSONL).read_text(encoding="utf-8").strip().splitlines()
    assert len(warn_lines) == 1  # only the well-formed one


def test_emit_no_diff_is_noop(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t.t")
    _git(repo, "config", "user.name", "t")
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    rc = lr._run(_ns(repo=str(repo), base="HEAD", ingest=None))
    assert rc == 0
    assert not (repo / lr.REQUEST_FILE).exists()  # nothing to review


def test_slug():
    assert lr._slug("Division by Zero!") == "division-by-zero"
    assert lr._slug("") == "finding"


class _ns:
    def __init__(self, **kw):
        self.__dict__.update(kw)
