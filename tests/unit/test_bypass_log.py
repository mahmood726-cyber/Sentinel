import subprocess
import sys
from pathlib import Path

SENTINEL_ROOT = Path(__file__).parent.parent.parent


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(SENTINEL_ROOT),
    )


def test_bypass_log_empty_prints_empty_message(tmp_path, monkeypatch):
    empty_log = tmp_path / "bypass.log"
    monkeypatch.setenv("SENTINEL_BYPASS_LOG", str(empty_log))
    res = _run("bypass-log")
    assert res.returncode == 0
    assert "empty" in res.stdout.lower() or res.stdout.strip() == ""


def test_bypass_log_prints_entries(tmp_path, monkeypatch):
    log = tmp_path / "bypass.log"
    log.write_text("2026-04-14T10:00Z\tshifaa\tmahmood\n", encoding="utf-8")
    monkeypatch.setenv("SENTINEL_BYPASS_LOG", str(log))
    res = _run("bypass-log")
    assert res.returncode == 0
    assert "shifaa" in res.stdout


def test_bypass_log_clear_empties_file(tmp_path, monkeypatch):
    log = tmp_path / "bypass.log"
    log.write_text("2026-04-14T10:00Z\tshifaa\tmahmood\n", encoding="utf-8")
    monkeypatch.setenv("SENTINEL_BYPASS_LOG", str(log))
    res = _run("bypass-log", "--clear")
    assert res.returncode == 0
    assert log.read_text(encoding="utf-8") == ""
