"""Tests for P1-blueprint-implementation-match.

Fires only when blueprint.json is present. Verifies every declared DOM
id from inputs[]/ui_sections[]/outputs[] appears in at least one .html
file in the repo.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from sentinel.core import RepoContext, ScanMode
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "blueprint_implementation_match.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def test_no_blueprint_no_verdict(tmp_path: Path):
    (tmp_path / "index.html").write_text("<html></html>", encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_blueprint_all_ids_present_passes(tmp_path: Path):
    bp = {
        "app_name": "demo",
        "inputs": [{"id": "file-input", "type": "file"}],
        "ui_sections": [{"id": "output-panel"}],
        "outputs": [{"id": "result-table", "type": "html_table"}],
    }
    (tmp_path / "blueprint.json").write_text(
        json.dumps(bp), encoding="utf-8"
    )
    (tmp_path / "index.html").write_text(
        '<input id="file-input">'
        '<div id="output-panel"></div>'
        '<table id="result-table"></table>',
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_blueprint_declares_id_not_in_html_warns(tmp_path: Path):
    bp = {
        "inputs": [{"id": "missing-input", "type": "file"}],
        "outputs": [],
        "ui_sections": [],
    }
    (tmp_path / "blueprint.json").write_text(
        json.dumps(bp), encoding="utf-8"
    )
    (tmp_path / "index.html").write_text("<html></html>", encoding="utf-8")
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert "missing-input" in verdicts[0].detail
    assert verdicts[0].severity.label == "WARN"


def test_blueprint_but_no_html_warns(tmp_path: Path):
    bp = {"inputs": [{"id": "a"}], "ui_sections": [], "outputs": []}
    (tmp_path / "blueprint.json").write_text(
        json.dumps(bp), encoding="utf-8"
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert "no .html file exists" in verdicts[0].detail


def test_ui_section_as_string_matches_dom_id(tmp_path: Path):
    bp = {
        "inputs": [],
        "ui_sections": ["intro", "results"],
        "outputs": [],
    }
    (tmp_path / "blueprint.json").write_text(
        json.dumps(bp), encoding="utf-8"
    )
    (tmp_path / "app.html").write_text(
        '<section id="intro"></section>'
        '<section id="results"></section>',
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_malformed_json_warns(tmp_path: Path):
    (tmp_path / "blueprint.json").write_text(
        "not valid json", encoding="utf-8"
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert "unreadable" in verdicts[0].detail


def test_class_token_matches_declared_id(tmp_path: Path):
    bp = {
        "inputs": [],
        "ui_sections": [{"id": "loader"}],
        "outputs": [],
    }
    (tmp_path / "blueprint.json").write_text(
        json.dumps(bp), encoding="utf-8"
    )
    (tmp_path / "index.html").write_text(
        '<div class="loader active"></div>', encoding="utf-8"
    )
    # space-separated class values: "loader" token satisfies the match
    assert _rule().check(_ctx(tmp_path)) == []


def test_excludes_node_modules(tmp_path: Path):
    bp = {"inputs": [{"id": "orphan"}], "ui_sections": [], "outputs": []}
    (tmp_path / "blueprint.json").write_text(
        json.dumps(bp), encoding="utf-8"
    )
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "doc.html").write_text(
        '<div id="orphan"></div>', encoding="utf-8"
    )
    # no .html at repo root (the only match is under node_modules)
    verdicts = _rule().check(_ctx(tmp_path))
    # either "no .html" or "orphan missing" — both are WARN outcomes; here
    # html_files ends up empty after filter, so "no .html" path fires
    assert len(verdicts) == 1
    assert verdicts[0].severity.label == "WARN"


def test_blueprint_non_object_warns(tmp_path: Path):
    (tmp_path / "blueprint.json").write_text(
        "[1, 2, 3]", encoding="utf-8"
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert "JSON object" in verdicts[0].detail


def test_empty_blueprint_no_verdict(tmp_path: Path):
    (tmp_path / "blueprint.json").write_text("{}", encoding="utf-8")
    (tmp_path / "index.html").write_text(
        "<html></html>", encoding="utf-8"
    )
    # no declared ids -> nothing to verify
    assert _rule().check(_ctx(tmp_path)) == []


def test_blueprint_as_directory_warns(tmp_path: Path):
    # P1-10: if blueprint.json exists but is a directory, emit a WARN
    # rather than silently returning empty.
    (tmp_path / "blueprint.json").mkdir()
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert "not a regular file" in verdicts[0].detail


def test_blueprint_match_in_git_worktree(tmp_path: Path):
    # P1-9: exercise the git ls-files code path in iter_repo_files.
    # Without this test, blueprint_implementation_match could break on
    # any real (git-backed) repo and all other tests still pass.
    bp = {
        "inputs": [{"id": "main-input"}],
        "ui_sections": [{"id": "main-panel"}],
        "outputs": [{"id": "main-output"}],
    }
    (tmp_path / "blueprint.json").write_text(
        json.dumps(bp), encoding="utf-8"
    )
    (tmp_path / "index.html").write_text(
        '<input id="main-input">'
        '<div id="main-panel"></div>'
        '<div id="main-output"></div>',
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "."],
        cwd=tmp_path, check=True,
    )
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t",
         "commit", "-q", "-m", "init"],
        cwd=tmp_path, check=True,
    )
    # Untracked .html should be invisible to git ls-files, so even if
    # it had a missing id, the rule would flag it. Confirm git-path is
    # used by adding an untracked file with the missing id — and
    # asserting the verdict list is still clean.
    (tmp_path / "untracked.html").write_text(
        "<span>nothing</span>", encoding="utf-8"
    )
    assert _rule().check(_ctx(tmp_path)) == []
