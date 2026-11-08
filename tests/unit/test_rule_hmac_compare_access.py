# sentinel:skip-file — test text deliberately includes crypto comparison examples.
"""Fail-closed and legitimate-code controls for P0-hmac-compare-eq reads."""
from __future__ import annotations

import traceback
from pathlib import Path

import pytest

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.io.git_files import GitFileEnumerationError
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parents[2] / "sentinel" / "rules" / "plugins"
    / "hmac_compare_eq.py"
)

BAD = "if request_digest == expected_digest:\n    pass\n"


def _scan(root: Path):
    rule = load_plugin_rule(PLUGIN_PATH)
    return rule.check(RepoContext(repo_root=root, mode=ScanMode.REPO))


def test_inaccessible_candidate_cannot_silently_skip_crypto_block(
    tmp_path: Path, monkeypatch,
):
    candidate = tmp_path / "auth.py"
    candidate.write_text(BAD, encoding="utf-8")
    original_read = Path.read_text

    def inaccessible(self, *args, **kwargs):
        if self == candidate:
            raise PermissionError("PRIVATE_SYNTHETIC_FS_DIAGNOSTIC")
        return original_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", inaccessible)
    with pytest.raises(GitFileEnumerationError) as exc:
        _scan(tmp_path)
    assert "PRIVATE_SYNTHETIC_FS_DIAGNOSTIC" not in "".join(
        traceback.format_exception(exc.value)
    )


def test_readable_insecure_comparison_remains_block(tmp_path: Path):
    (tmp_path / "auth.py").write_text(BAD, encoding="utf-8")
    findings = _scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "P0-hmac-compare-eq"
    assert findings[0].severity == Severity.BLOCK


def test_legitimate_compare_and_excluded_unreadable_file_stay_clean(
    tmp_path: Path, monkeypatch,
):
    (tmp_path / "auth.py").write_text(
        "import hmac\nif hmac.compare_digest(request_digest, expected_digest):\n"
        "    pass\n",
        encoding="utf-8",
    )
    excluded = tmp_path / "node_modules" / "bad.py"
    excluded.parent.mkdir()
    excluded.write_text(BAD, encoding="utf-8")
    original_read = Path.read_text

    def unreadable_excluded(self, *args, **kwargs):
        if self == excluded:
            raise PermissionError("excluded test candidate")
        return original_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", unreadable_excluded)
    assert _scan(tmp_path) == []
