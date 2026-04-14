import json
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


def test_dashboard_renders_html_from_sweep(tmp_path: Path):
    sweep = {
        "generated_at": "2026-04-14T00:00:00+00:00",
        "repos_scanned": 1,
        "total_counts": {"BLOCK": 1, "WARN": 0, "INFO": 0},
        "per_repo": [{
            "repo": "C:/Projects/shifaa",
            "counts": {"BLOCK": 1, "WARN": 0, "INFO": 0},
            "verdicts": [{
                "rule_id": "P0-placeholder-hmac",
                "severity": "BLOCK",
                "repo": "C:/Projects/shifaa",
                "file": "cert.json",
                "line": 1,
                "detail": "hit",
                "fix_hint": "fix",
                "source": "lessons.md",
                "timestamp": "2026-04-14T00:00:00+00:00",
            }],
        }],
    }
    sweep_path = tmp_path / "sweep.json"
    sweep_path.write_text(json.dumps(sweep), encoding="utf-8")
    out = tmp_path / "dashboard.html"
    res = _run("dashboard", "--from", str(sweep_path), "--out", str(out))
    assert res.returncode == 0
    html = out.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html
    assert "shifaa" in html
    assert "P0-placeholder-hmac" in html
    # No external CDN resources per html-apps.md
    assert "http://" not in html
    assert "https://" not in html or html.count("https://") == 0


def test_dashboard_shows_zero_state_for_empty_sweep(tmp_path: Path):
    sweep_path = tmp_path / "sweep.json"
    sweep_path.write_text(json.dumps({
        "generated_at": "2026-04-14T00:00:00+00:00",
        "repos_scanned": 0,
        "total_counts": {"BLOCK": 0, "WARN": 0, "INFO": 0},
        "per_repo": [],
    }), encoding="utf-8")
    out = tmp_path / "d.html"
    res = _run("dashboard", "--from", str(sweep_path), "--out", str(out))
    assert res.returncode == 0
    html = out.read_text(encoding="utf-8")
    assert "No repos" in html or "0 repos" in html.lower() or "repos_scanned" in html.lower()
