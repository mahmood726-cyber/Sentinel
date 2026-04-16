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


# Bypass-log discard-target rejection (P1-6 hardening, 2026-04-15 review).
# Redirecting SENTINEL_BYPASS_LOG to /dev/null or NUL would create a
# silent-bypass hole — an attacker could bypass and erase the audit
# trail. Both the hook payload (bash) and the CLI (Python) must reject.

def test_bypass_log_rejects_dev_null(monkeypatch):
    monkeypatch.setenv("SENTINEL_BYPASS_LOG", "/dev/null")
    res = _run("bypass-log")
    assert res.returncode == 1
    assert "/dev/null" in res.stdout or "/dev/null" in res.stderr
    assert "discard target" in (res.stdout + res.stderr).lower()


def test_bypass_log_rejects_nul_windows(monkeypatch):
    monkeypatch.setenv("SENTINEL_BYPASS_LOG", "NUL")
    res = _run("bypass-log")
    assert res.returncode == 1
    out = res.stdout + res.stderr
    assert "NUL" in out
    assert "discard target" in out.lower()


def test_bypass_log_rejects_whitespace_only(monkeypatch):
    """A whitespace-only path normalises to empty after .strip() and must
    be treated as discard. Otherwise an attacker could bypass detection
    by setting SENTINEL_BYPASS_LOG=' ' (which writes nowhere)."""
    monkeypatch.setenv("SENTINEL_BYPASS_LOG", "   ")
    res = _run("bypass-log")
    assert res.returncode == 1
    assert "discard target" in (res.stdout + res.stderr).lower()


def test_bypass_log_accepts_normal_file(tmp_path, monkeypatch):
    """Sanity: hardening must not break the legitimate path. A real file
    under tmp_path still works exactly like before."""
    log = tmp_path / "bypass.log"
    log.write_text("entry\n", encoding="utf-8")
    monkeypatch.setenv("SENTINEL_BYPASS_LOG", str(log))
    res = _run("bypass-log")
    assert res.returncode == 0
    assert "entry" in res.stdout
