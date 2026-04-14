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
