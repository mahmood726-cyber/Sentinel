"""Synthetic failure/clean controls for the E156 placeholder guard.

A known root-level artifact that cannot be inspected must not turn a
published-content BLOCK into a successful Sentinel scan.
"""
from __future__ import annotations

import traceback
from pathlib import Path

import pytest

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.io.git_files import GitFileEnumerationError
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parents[2] / "sentinel" / "rules" / "plugins"
    / "e156_placeholder_leak.py"
)


def _check(root: Path):
    rule = load_plugin_rule(PLUGIN_PATH)
    return rule.check(RepoContext(repo_root=root, mode=ScanMode.REPO))


@pytest.mark.parametrize(
    "filename,content",
    [
        ("students.html", "<script>const rates = {publishedHR: None};</script>"),
        ("rewrite-workbook.txt", "  Code: None\n"),
    ],
)
def test_unreadable_known_candidate_aborts_instead_of_missing_block(
    tmp_path: Path, monkeypatch, filename: str, content: str,
):
    candidate = tmp_path / filename
    candidate.write_text(content, encoding="utf-8")
    original = Path.read_text

    def deny_known_candidate(self, *args, **kwargs):
        if self == candidate:
            raise PermissionError("PRIVATE_SYNTHETIC_DETAIL_DO_NOT_EXPOSE")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", deny_known_candidate)
    with pytest.raises(GitFileEnumerationError) as exc:
        _check(tmp_path)
    assert "PRIVATE_SYNTHETIC_DETAIL_DO_NOT_EXPOSE" not in str(exc.value)
    assert "PRIVATE_SYNTHETIC_DETAIL_DO_NOT_EXPOSE" not in "".join(
        traceback.format_exception(exc.value)
    )


def test_failed_candidate_is_file_check_aborts(tmp_path: Path, monkeypatch):
    candidate = tmp_path / "students.html"
    candidate.write_text("<script>const x = {hr: None}</script>", encoding="utf-8")
    original = Path.is_file

    def deny_candidate_status(self):
        if self == candidate:
            raise PermissionError("PRIVATE_SYNTHETIC_STATUS_DETAIL")
        return original(self)

    monkeypatch.setattr(Path, "is_file", deny_candidate_status)
    with pytest.raises(GitFileEnumerationError) as exc:
        _check(tmp_path)
    assert "PRIVATE_SYNTHETIC_STATUS_DETAIL" not in "".join(
        traceback.format_exception(exc.value)
    )


def test_existing_bad_artifacts_still_block(tmp_path: Path):
    (tmp_path / "students.html").write_text(
        "<script>const data = {publishedHR: None};</script>", encoding="utf-8"
    )
    (tmp_path / "rewrite-workbook.txt").write_text(
        "  Protocol: None\n", encoding="utf-8"
    )
    verdicts = _check(tmp_path)
    assert len([v for v in verdicts if v.severity == Severity.BLOCK]) == 2
    assert {v.file for v in verdicts} == {
        "students.html", "rewrite-workbook.txt"
    }


def test_valid_artifacts_and_unrelated_files_do_not_block(tmp_path: Path, monkeypatch):
    (tmp_path / "students.html").write_text(
        "<script>const data = {publishedHR: null};</script>", encoding="utf-8"
    )
    (tmp_path / "rewrite-workbook.txt").write_text(
        "  Code: https://example.org/program\n", encoding="utf-8"
    )
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_text("not a scanned artifact", encoding="utf-8")
    original = Path.read_text

    def deny_unrelated(self, *args, **kwargs):
        if self == unrelated:
            raise PermissionError("irrelevant file")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", deny_unrelated)
    assert _check(tmp_path) == []
