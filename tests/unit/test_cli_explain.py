import subprocess
import sys
from pathlib import Path

SENTINEL_ROOT = Path(__file__).parent.parent.parent


def test_explain_known_rule_prints_source_and_fix_hint():
    res = subprocess.run(
        [sys.executable, "-m", "sentinel", "explain", "P0-placeholder-hmac"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(SENTINEL_ROOT),
    )
    assert res.returncode == 0
    assert "lessons.md" in res.stdout
    assert "TRUTHCERT_HMAC_KEY" in res.stdout


def test_explain_unknown_rule_exits_one():
    res = subprocess.run(
        [sys.executable, "-m", "sentinel", "explain", "NONEXISTENT"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(SENTINEL_ROOT),
    )
    assert res.returncode == 1
    assert "unknown rule" in (res.stdout + res.stderr).lower()
