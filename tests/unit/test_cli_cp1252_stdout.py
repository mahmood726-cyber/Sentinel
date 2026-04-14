"""Regression: CLI must not crash on non-ASCII chars in verdict details.

Bug discovered 2026-04-14 during metasprint-autopilot pre-push. A WARN
verdict detail contained the intersection symbol ∩ (U+2229) from a
statistics formula. On Windows, sys.stdout defaults to cp1252, which
cannot encode U+2229 → print() raised UnicodeEncodeError → scan exited 10
(internal error) → push blocked on a clean-scan repo.

Per lessons.md#platform, CLIs on Windows must wrap stdout/stderr in
UTF-8 before printing. Fix is at the CLI entry point so all subcommands
benefit.
"""
from __future__ import annotations
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_scan_does_not_crash_on_non_ascii_verdict_detail_under_cp1252(tmp_path):
    """PYTHONIOENCODING=cp1252 reproduces Windows default; ∩ in a WARN
    detail must not crash the scan."""
    repo = tmp_path / "unicode-repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)

    # Trigger P1-unpopulated-placeholder with a non-ASCII char inside the
    # matched pattern. The WARN detail will include "∩".
    (repo / "stats.py").write_text(
        "A = {{ x ∩ y }}  # intersection symbol in a placeholder\n",
        encoding="utf-8",
    )

    env = {**os.environ, "PYTHONIOENCODING": "cp1252"}
    res = subprocess.run(
        [sys.executable, "-m", "sentinel", "scan", "--repo", str(repo)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=30,
    )

    assert res.returncode != 10, (
        f"scan crashed with exit 10 on non-ASCII verdict detail (cp1252 stdout). "
        f"This is the 2026-04-14 regression. stderr head: {res.stderr[:400]}"
    )
    assert "UnicodeEncodeError" not in res.stderr, (
        f"stdout encoding not reconfigured; UnicodeEncodeError in stderr: "
        f"{res.stderr[:400]}"
    )
    assert "[Sentinel] verdicts:" in res.stdout, (
        f"expected verdicts summary in stdout: {res.stdout[:400]}"
    )
