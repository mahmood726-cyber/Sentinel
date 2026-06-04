"""Smoke tests for the sentinel CLI.

M1 coverage config scoped out CLI. These tests close that gap with subprocess-
level checks: each subcommand runs, prints expected output, and returns the
documented exit code.
"""
from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]


def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        cwd=cwd or REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_help_exits_0():
    r = _run("--help")
    assert r.returncode == 0
    assert "scan" in r.stdout
    assert "list-rules" in r.stdout


def test_list_rules_text():
    r = _run("list-rules")
    assert r.returncode == 0
    assert "P0-placeholder-hmac" in r.stdout
    assert "P0-hardcoded-local-path" in r.stdout
    assert "[BLOCK]" in r.stdout


def test_list_rules_json():
    r = _run("list-rules", "--json")
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert isinstance(data, list)
    assert len(data) >= 5
    ids = [r["id"] for r in data]
    assert "P0-placeholder-hmac" in ids


def test_explain_known_rule():
    r = _run("explain", "P0-placeholder-hmac")
    assert r.returncode == 0
    assert "P0-placeholder-hmac" in r.stdout
    assert "Severity" in r.stdout


def test_explain_json():
    r = _run("explain", "P0-placeholder-hmac", "--json")
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert data["id"] == "P0-placeholder-hmac"
    assert data["severity"] == "BLOCK"


def test_explain_unknown_rule_exits_1():
    r = _run("explain", "P0-does-not-exist")
    assert r.returncode == 1
    assert "unknown rule id" in r.stderr


def test_scan_missing_repo_exits_2(tmp_path: Path):
    """Fail-closed on non-existent path — regression against silent fail-open."""
    r = _run("scan", "--repo", str(tmp_path / "does-not-exist"))
    assert r.returncode == 2
    assert "does not exist" in r.stderr


def test_scan_help_uses_projectindex_audit_default():
    r = _run("scan", "--help")
    assert r.returncode == 0
    assert "C:/Projects/projectindex-audit" in r.stdout


def test_scan_non_git_dir_exits_2(tmp_path: Path):
    """Fail-closed on a real dir that isn't a git repo."""
    r = _run("scan", "--repo", str(tmp_path))
    assert r.returncode == 2
    assert "not a git repository" in r.stderr


def test_scan_empty_git_repo_exits_0(tmp_path: Path):
    """Empty git repo: valid, no findings, exit 0."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    r = _run("scan", "--repo", str(tmp_path))
    assert r.returncode == 0
    assert "BLOCK=0" in r.stdout


def test_scan_json_output(tmp_path: Path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    r = _run("scan", "--repo", str(tmp_path), "--json")
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert "verdicts" in data
    assert data["verdicts"] == []
