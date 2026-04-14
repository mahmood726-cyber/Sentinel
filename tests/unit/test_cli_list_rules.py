import subprocess
import sys
from pathlib import Path

SENTINEL_ROOT = Path(__file__).parent.parent.parent


def test_list_rules_prints_all_three():
    res = subprocess.run(
        [sys.executable, "-m", "sentinel", "list-rules"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(SENTINEL_ROOT),
    )
    assert res.returncode == 0
    out = res.stdout
    assert "P0-placeholder-hmac" in out
    assert "P0-path-not-exist" in out
    assert "P0-registry-drift" in out
