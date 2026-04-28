"""Tests for `sentinel scan --timing` per-rule perf instrumentation.

Adds visibility into which rule is the bottleneck — useful when Sentinel
itself starts taking >2s on large repos and you need to know whether the
slow rule is e.g. registry_drift (network) or html_a11y_basics (file I/O).

The flag is opt-in (off by default) to keep regular scan output stable.
"""
from __future__ import annotations
import re
import subprocess
import sys
from pathlib import Path

SENTINEL_ROOT = Path(__file__).parent.parent.parent


def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(cwd or SENTINEL_ROOT),
    )


def test_timing_flag_prints_per_rule_durations(tmp_path: Path):
    clean = tmp_path / "clean"
    clean.mkdir()
    subprocess.run(["git", "init", "-q", str(clean)], check=True)
    res = _run("scan", "--repo", str(clean), "--timing")
    assert res.returncode == 0, f"stderr: {res.stderr}"
    # Expect at least one line like:  [timing]  P0-hardcoded-local-path  0.012s
    assert "[timing]" in res.stdout, \
        f"expected '[timing]' in stdout, got: {res.stdout}"
    # And a total line
    assert re.search(r"\[timing\]\s+TOTAL\s+\d+\.\d{3}s", res.stdout), \
        f"expected total timing line, got: {res.stdout}"


def test_timing_off_by_default_no_timing_lines(tmp_path: Path):
    clean = tmp_path / "clean"
    clean.mkdir()
    subprocess.run(["git", "init", "-q", str(clean)], check=True)
    res = _run("scan", "--repo", str(clean))
    assert res.returncode == 0
    assert "[timing]" not in res.stdout, \
        f"expected no '[timing]' without --timing flag, got: {res.stdout}"
