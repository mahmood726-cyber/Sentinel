import json
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


def _git_init(path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(path)], check=True)


def test_scan_repo_mode_exits_zero_on_clean_repo(tmp_path: Path):
    clean = tmp_path / "clean"
    clean.mkdir()
    _git_init(clean)
    (clean / "hello.txt").write_text("hello", encoding="utf-8")
    res = _run("scan", "--repo", str(clean))
    assert res.returncode == 0, f"stderr: {res.stderr}"


def test_scan_repo_mode_exits_one_on_placeholder_hmac(tmp_path: Path):
    bad = tmp_path / "bad"
    bad.mkdir()
    _git_init(bad)
    (bad / "cert.json").write_text(
        '{"sig":"SIG_RSA_SHA256_x"}', encoding="utf-8"
    )
    res = _run("scan", "--repo", str(bad))
    assert res.returncode == 1
    assert "P0-placeholder-hmac" in res.stdout + res.stderr
    assert (bad / "STUCK_FAILURES.md").exists()


def test_scan_json_output_contains_verdicts(tmp_path: Path):
    bad = tmp_path / "bad"
    bad.mkdir()
    _git_init(bad)
    (bad / "cert.json").write_text(
        '{"sig":"SIG_RSA_SHA256_x"}', encoding="utf-8"
    )
    res = _run("scan", "--repo", str(bad), "--json")
    assert res.returncode == 1
    data = json.loads(res.stdout)
    assert any(v["rule_id"] == "P0-placeholder-hmac" for v in data["verdicts"])
