"""Tests for P2-numeric-parse-or-null.

Fires on `parseFloat(x) || null` / `parseInt(x) || 0` / `Number(x) || undefined`
shapes that silently drop legitimate zero values. Past incident:
lessons.md "parseFloat(x) || null drops 0.0".
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "numeric_parse_or_null.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def test_severity_is_warn(tmp_path):
    """Warn (not block) — non-numeric fallbacks like `|| "default"` are
    legitimate; only specific zero-droppers are flagged."""
    assert _rule().severity == Severity.WARN


def test_fires_on_parsefloat_or_null(tmp_path):
    (tmp_path / "bad.js").write_text("const v = parseFloat(x) || null;\n", encoding="utf-8")
    assert len(_rule().check(_ctx(tmp_path))) == 1


def test_fires_on_parseint_or_zero(tmp_path):
    (tmp_path / "bad.js").write_text("const v = parseInt(x) || 0;\n", encoding="utf-8")
    assert len(_rule().check(_ctx(tmp_path))) == 1


def test_fires_on_number_or_undefined(tmp_path):
    (tmp_path / "bad.js").write_text("const v = Number(x) || undefined;\n", encoding="utf-8")
    assert len(_rule().check(_ctx(tmp_path))) == 1


def test_quiet_when_canonical_fix_used(tmp_path):
    (tmp_path / "good.js").write_text(
        "const p = parseFloat(x);\n"
        "const v = Number.isFinite(p) ? p : null;\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_with_nullish_coalescing(tmp_path):
    """parseFloat(x) ?? null preserves 0 because ?? only catches nullish."""
    (tmp_path / "good.js").write_text("const v = parseFloat(x) ?? null;\n", encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_with_non_numeric_default(tmp_path):
    """`|| 'default'` is intentional — operator wants a string fallback,
    not silently treating 0 as missing."""
    (tmp_path / "good.js").write_text(
        "const v = parseFloat(x) || 'default';\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []
