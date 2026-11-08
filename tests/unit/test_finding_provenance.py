"""Tests for finding provenance: every written finding carries `commit` and
`tracked`.

Why these exist (2026-08-30 historical replay):

Replaying 452 historical BLOCK findings against the commit each was raised at
was impossible from the record itself -- a finding carried only a `timestamp`,
so the commit had to be reconstructed with `git rev-list -n1 --before=<ts>`,
which is a guess. And because Sentinel scans the working tree INCLUDING
untracked files, a finding about a file that exists in no commit looked exactly
like one about committed code: 12 of 19 apparent "detector gaps" were that
confusion, and a hand-check collapsed 18 accusations to 0.

These tests pin the REQUIREMENT (the two fields are present and correct), not
any message wording. Each positive has a negative twin, so the fields cannot
satisfy the suite by being hardcoded to one value.
"""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinel.core import Severity, Verdict
from sentinel.io.paths import BLOCK_JSONL
from sentinel.io import provenance
from sentinel.io.writer import write_findings


def _git(root: Path, *args: str):
    return subprocess.run(["git", "-C", str(root), *args],
                          capture_output=True, text=True, timeout=30,
                          stdin=subprocess.DEVNULL)


def _repo(tmp_path: Path) -> Path:
    """A real git repo with one committed file and one untracked file."""
    provenance._reset_caches_for_tests()
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@t.t")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "committed.py").write_text("x = 1\n", encoding="utf-8")
    _git(tmp_path, "add", "committed.py")
    _git(tmp_path, "commit", "-qm", "init")
    (tmp_path / "untracked.py").write_text("y = 2\n", encoding="utf-8")
    return tmp_path


def _verdict(rel: str) -> Verdict:
    return Verdict(
        rule_id="P0-test", severity=Severity.BLOCK, repo="r", file=rel, line=1,
        detail="d", fix_hint="f", source="s",
        timestamp=datetime.now(timezone.utc),
    )


def _written(root: Path):
    lines = (root / BLOCK_JSONL).read_text(encoding="utf-8").strip().split("\n")
    return [json.loads(x) for x in lines if x.strip()]


def _has_git():
    try:
        return subprocess.run(["git", "--version"], capture_output=True,
                              timeout=15).returncode == 0
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _has_git(), reason="git not available")


# ------------------------------------------------------------- commit field


def test_finding_records_the_commit_it_was_raised_against(tmp_path):
    """Without this, the commit can only be guessed from the timestamp."""
    root = _repo(tmp_path)
    head = _git(root, "rev-parse", "HEAD").stdout.strip()
    write_findings(root, [_verdict("committed.py")])
    rec = _written(root)[0]
    assert "commit" in rec, "finding must carry a commit field"
    assert rec["commit"] == head, (
        "commit must be the HEAD at scan time: expected %r got %r"
        % (head, rec.get("commit")))


def test_commit_is_none_outside_a_git_repo(tmp_path):
    """An honest unknown, never a fabricated SHA."""
    provenance._reset_caches_for_tests()
    (tmp_path / "committed.py").write_text("x = 1\n", encoding="utf-8")
    write_findings(tmp_path, [_verdict("committed.py")])
    assert _written(tmp_path)[0]["commit"] is None


# ------------------------------------------------------------ tracked field


def test_tracked_true_for_a_committed_file(tmp_path):
    root = _repo(tmp_path)
    write_findings(root, [_verdict("committed.py")])
    rec = _written(root)[0]
    assert "tracked" in rec, "finding must carry a tracked field"
    assert rec["tracked"] is True


def test_tracked_false_for_an_untracked_file(tmp_path):
    """THE case that manufactured 18 false detector gaps: a finding against a
    file that exists in no commit must be distinguishable from a committed one."""
    root = _repo(tmp_path)
    write_findings(root, [_verdict("untracked.py")])
    rec = _written(root)[0]
    assert rec["tracked"] is False, (
        "an untracked file must be recorded as tracked=False, otherwise a "
        "working-tree finding is indistinguishable from a committed one")


def test_tracked_is_none_for_a_repo_wide_finding(tmp_path):
    """No file means the question does not apply -- None, not False."""
    root = _repo(tmp_path)
    write_findings(root, [_verdict(None)])
    assert _written(root)[0]["tracked"] is None


def test_tracked_is_none_outside_a_git_repo(tmp_path):
    """Unknown, not False: an empty tracked set would mark everything untracked."""
    provenance._reset_caches_for_tests()
    (tmp_path / "committed.py").write_text("x = 1\n", encoding="utf-8")
    write_findings(tmp_path, [_verdict("committed.py")])
    assert _written(tmp_path)[0]["tracked"] is None


# ------------------------------------------------ the two fields disagree
# (a single hardcoded value cannot satisfy both of these)


def test_tracked_distinguishes_the_two_files_in_one_run(tmp_path):
    root = _repo(tmp_path)
    write_findings(root, [_verdict("committed.py"), _verdict("untracked.py")])
    recs = {r["file"]: r["tracked"] for r in _written(root)}
    assert recs["committed.py"] is True
    assert recs["untracked.py"] is False
