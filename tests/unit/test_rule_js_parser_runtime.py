"""Fail-closed and ordinary-push controls for the JavaScript parser runtime.

All fixtures are synthetic.  Missing parser infrastructure must not make
tracked JavaScript appear syntax-clean in warn-mode hooks.
"""
from __future__ import annotations

import shutil
import subprocess
import traceback
from pathlib import Path

import pytest

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.io.git_files import GitFileEnumerationError
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parents[2] / "sentinel" / "rules" / "plugins"
    / "js_parse_check.py"
)
BAD_JS = "function broken( {\n"
GOOD_JS = "const answer = 42;\n"


def _scan(root: Path):
    return load_plugin_rule(PLUGIN_PATH).check(
        RepoContext(repo_root=root, mode=ScanMode.REPO)
    )


def _write(root: Path, name: str, content: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_node_missing_with_js_candidate_is_fatal_not_clean(tmp_path: Path, monkeypatch):
    _write(tmp_path, "src/bad.js", BAD_JS)
    monkeypatch.setattr(shutil, "which", lambda executable: None)
    with pytest.raises(GitFileEnumerationError, match="JavaScript|node"):
        _scan(tmp_path)


def test_node_missing_with_only_excluded_or_skipped_js_is_clean(
    tmp_path: Path, monkeypatch,
):
    _write(tmp_path, "node_modules/bad.js", BAD_JS)
    _write(tmp_path, "build/bad.mjs", BAD_JS)
    _write(tmp_path, "src/bundle.min.js", BAD_JS)
    _write(tmp_path, "src/intentional.cjs", "// sentinel:skip-file\n" + BAD_JS)
    monkeypatch.setattr(shutil, "which", lambda executable: None)
    assert _scan(tmp_path) == []


@pytest.mark.parametrize("failure", ["missing_executable", "timeout"])
def test_node_execution_failure_cannot_become_downgradable_block(
    tmp_path: Path, monkeypatch, failure: str,
):
    _write(tmp_path, "src/bad.js", BAD_JS)
    monkeypatch.setattr(shutil, "which", lambda executable: "/synthetic/node")

    def fail_node(*args, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(
                cmd="node --check", timeout=10,
                stderr=b"PRIVATE_SYNTHETIC_DIAGNOSTIC",
            )
        raise FileNotFoundError("PRIVATE_SYNTHETIC_DIAGNOSTIC")

    monkeypatch.setattr(subprocess, "run", fail_node)
    with pytest.raises(GitFileEnumerationError) as exc:
        _scan(tmp_path)
    rendered = "".join(traceback.format_exception(exc.value))
    assert "PRIVATE_SYNTHETIC_DIAGNOSTIC" not in rendered


@pytest.mark.parametrize(
    ("source", "returncode", "expected_block"),
    [(BAD_JS, 1, True), (GOOD_JS, 0, False)],
)
def test_node_runs_normally_and_does_not_block_valid_code(
    tmp_path: Path, monkeypatch, source: str, returncode: int,
    expected_block: bool,
):
    _write(tmp_path, "src/candidate.js", source)
    monkeypatch.setattr(shutil, "which", lambda executable: "/synthetic/node")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=["node", "--check"], returncode=returncode,
            stdout="", stderr="SyntaxError: synthetic bad JS" if returncode else "",
        ),
    )
    verdicts = _scan(tmp_path)
    if expected_block:
        assert len(verdicts) == 1
        assert verdicts[0].rule_id == "P1-js-parse-check"
        assert verdicts[0].severity == Severity.BLOCK
        assert verdicts[0].file == "src/candidate.js"
    else:
        assert verdicts == []
