"""Regression: scan CLI fail-closes on internal crash.

Exit code contract per sentinel/cli/scan.py:
  10 on uncaught exception (NOT treated as findings).
  Hook treats exit >=10 as fail-closed regardless of warn/block mode.

This prevents a broken Sentinel from silently stopping enforcement across
the portfolio (the S8 stress-test finding).
"""
from __future__ import annotations
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_scan_returns_10_on_registry_load_failure(tmp_path, monkeypatch):
    """If Registry.from_dir raises, scan must exit 10 (not 0, not 1).

    We simulate a crash by pointing RULES_ROOT at a nonexistent dir via
    monkey-patching. from_dir raises EmptyRegistryError → scan catches and
    exits 10.
    """
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)

    # Run scan in a subprocess with a sitecustomize that patches RULES_ROOT
    # to a path guaranteed to fail. Simpler: write a rules dir with a
    # malformed YAML that raises YamlRuleLoadError.
    bad_rules = tmp_path / "fake_rules"
    (bad_rules / "yaml").mkdir(parents=True)
    (bad_rules / "yaml" / "bad.yaml").write_text(
        "this is not: valid: yaml: structure: at: all:\n  - [missing\n",
        encoding="utf-8",
    )

    # Monkeypatch via PYTHONPATH + sitecustomize injection
    sitecustomize = tmp_path / "sitecustomize.py"
    sitecustomize.write_text(
        f"from pathlib import Path\n"
        f"import sentinel.cli.scan as s\n"
        f"s.RULES_ROOT = Path(r'{bad_rules}')\n",
        encoding="utf-8",
    )
    env = {
        "PYTHONPATH": subprocess.os.pathsep.join([str(tmp_path), str(REPO_ROOT)]),
        "PATH": subprocess.os.environ.get("PATH", ""),
    }

    res = subprocess.run(
        [sys.executable, "-m", "sentinel", "scan", "--repo", str(tmp_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env={**subprocess.os.environ, **env},
        timeout=30,
    )
    assert res.returncode == 10, (
        f"expected exit 10 on scan crash, got {res.returncode}. "
        f"stdout={res.stdout[:300]} stderr={res.stderr[:300]}"
    )
    assert "INTERNAL ERROR" in res.stderr
    assert "NOT a clean scan" in res.stderr


def test_empty_diff_emits_verdicts_marker(tmp_path):
    """A --diff scan with no changed files (e.g. a branch/tag DELETION push)
    must still print the verdicts marker so the hook's proof-of-run check
    reads it as a clean 0-findings pass, not a crash.

    Regression: previously this path returned 0 WITHOUT a marker, so the
    pre-push hook blocked every branch deletion and forced SENTINEL_BYPASS.
    """
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path),
                    "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-q", "--allow-empty", "-m", "init"], check=True)

    # --diff against HEAD with a clean tree -> no changed files.
    res = subprocess.run(
        [sys.executable, "-m", "sentinel", "scan", "--repo", str(tmp_path),
         "--diff", "--base-ref", "HEAD"],
        cwd=REPO_ROOT, capture_output=True, text=True,
        env=subprocess.os.environ, timeout=30,
    )
    assert res.returncode == 0, (
        f"empty diff should exit 0, got {res.returncode}. "
        f"stdout={res.stdout[:300]} stderr={res.stderr[:300]}"
    )
    assert "nothing to scan" in res.stdout
    assert "[Sentinel] verdicts:" in res.stdout, (
        "empty-diff scan must emit the verdicts marker (proof-of-run) so the "
        f"hook does not misread it as a crash. stdout={res.stdout[:300]}"
    )


def test_hook_payload_fails_closed_on_crash_exit_code():
    """Static check: hook payload script explicitly handles rc>=10 as BLOCK,
    AND requires a verdicts-marker in scan output (proof-of-run).

    Both guards must come BEFORE the warn-mode silencer, otherwise warn mode
    would silence a crash whose exit code is 1 (Python's default for
    ImportError/SyntaxError).
    """
    from sentinel.hook.payload import make_hook_script

    for mode in ("warn", "block"):
        script = make_hook_script(mode)
        verdicts_guard_idx = script.find("did NOT produce verdicts")
        crash_idx = script.find("rc -ge 10")
        warn_idx = script.find('MODE" = "warn"')
        assert verdicts_guard_idx > 0, (
            f"hook ({mode}) missing verdicts-marker guard "
            f"(warn mode would silence Python ImportError exit 1)"
        )
        assert crash_idx > 0, f"hook script ({mode}) missing rc>=10 crash handler"
        assert warn_idx > 0, f"hook script ({mode}) missing warn handler"
        assert verdicts_guard_idx < warn_idx, (
            f"verdicts-marker guard must come before warn silencer in {mode}-mode hook"
        )
        assert crash_idx < warn_idx, (
            f"crash handler must come before warn silencer in {mode}-mode hook"
        )


def test_hook_payload_grep_regex_valid():
    """The verdicts-marker grep regex must match actual scan output format."""
    import re
    from sentinel.hook.payload import make_hook_script

    script = make_hook_script("warn")
    # Expected scan output line from scan.py::_print_summary
    real_output = "[Sentinel] verdicts: BLOCK=0 WARN=0 INFO=0"
    json_output = '{\n  "verdicts": []\n}'

    # Extract the grep pattern from the script. Bash ERE `\[` and `\]` map
    # directly to Python regex literal brackets — no unescaping needed.
    m = re.search(r"grep -qE '\((.*?)\)'", script)
    assert m, "could not find verdicts-marker grep pattern in hook script"
    pattern = m.group(1)

    # These MUST match (proof-of-run):
    assert re.search(pattern, real_output), f"pattern {pattern!r} should match text output"
    assert re.search(pattern, json_output), f"pattern {pattern!r} should match JSON output"
    # These must NOT match (crash cases):
    assert not re.search(pattern, "Traceback (most recent call last):"), \
        "pattern should not match crash traceback"
    assert not re.search(pattern, "ImportError: ..."), \
        "pattern should not match ImportError"
