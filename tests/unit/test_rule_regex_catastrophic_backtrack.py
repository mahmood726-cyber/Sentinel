"""Tests for P1-regex-catastrophic-backtrack.

Fires on Python re.compile/match/etc. calls whose pattern contains a
nested unbounded quantifier with a wildcard inner — the canonical ReDoS
shape. Past incident: lessons.md "ReDoS: [\\w\\s]+? with nesting".

Narrowed 2026-05-25 to skip patterns with literal-character anchors
inside the inner group (those don't backtrack-explode in practice).
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "regex_catastrophic_backtrack.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def test_severity_is_warn(tmp_path):
    """Warn — failure is performance-only on benign input."""
    assert _rule().severity == Severity.WARN


def test_fires_on_word_class_nested(tmp_path):
    (tmp_path / "bad.py").write_text(
        'import re\np = re.compile(r"(\\w+)+")\n', encoding="utf-8"
    )
    assert len(_rule().check(_ctx(tmp_path))) == 1


def test_fires_on_lazy_then_greedy(tmp_path):
    (tmp_path / "bad.py").write_text(
        'import re\np = re.compile(r"(.+?)+x")\n', encoding="utf-8"
    )
    assert len(_rule().check(_ctx(tmp_path))) == 1


def test_fires_on_dot_star_outer(tmp_path):
    (tmp_path / "bad.py").write_text(
        'import re\np = re.compile(r"prefix(\\d+)*$")\n', encoding="utf-8"
    )
    assert len(_rule().check(_ctx(tmp_path))) == 1


def test_quiet_on_bare_quantifier(tmp_path):
    """A single `\\w+` without nesting is fine."""
    (tmp_path / "good.py").write_text(
        'import re\np = re.compile(r"\\w+")\n', encoding="utf-8"
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_bounded_inner(tmp_path):
    """{1,80} bounds the inner — no explosion possible."""
    (tmp_path / "good.py").write_text(
        'import re\np = re.compile(r"(\\w{1,80})+")\n', encoding="utf-8"
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_literal_anchored_inner(tmp_path):
    """The 2026-05-25 narrowing: char-anchored inner like `[/-]\\S+` is
    safe because each iteration must start with a specific char."""
    (tmp_path / "good.py").write_text(
        'import re\np = re.compile(r"(?:\\s+[/-]\\S+)*")\n', encoding="utf-8"
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_on_literal_group(tmp_path):
    """(abc)+ — no inner quantifier, no backtracking risk."""
    (tmp_path / "good.py").write_text(
        'import re\np = re.compile(r"(abc)+")\n', encoding="utf-8"
    )
    assert _rule().check(_ctx(tmp_path)) == []
