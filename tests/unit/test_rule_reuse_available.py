# sentinel:skip-file -- fixtures intentionally reimplement kit primitives to trip the rule.
"""Tests for P2-reuse-available: WARN when a file hand-rolls a shared-kit primitive."""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule

PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "reuse_available.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def _warns(verdicts):
    return [v for v in verdicts if v.severity == Severity.WARN and v.rule_id == "P2-reuse-available"]


def test_handrolled_forest_with_svgel_contract_warns(tmp_path):
    (tmp_path / "myplot.js").write_text(
        "function renderForest(svgEl, studies, opts) {\n"
        "  // a from-scratch forest plot\n"
        "  return svgEl;\n}\n",
        encoding="utf-8",
    )
    w = _warns(_rule().check(_ctx(tmp_path)))
    assert len(w) == 1
    assert "renderForest" in w[0].detail and "e156-chart-kit" in w[0].detail


def test_assignment_and_arrow_forms_warn(tmp_path):
    (tmp_path / "a.js").write_text(
        "const renderFunnel = function(svgEl, points, opts) { return svgEl; };\n",
        encoding="utf-8")
    (tmp_path / "b.js").write_text(
        "renderGOSH = (svgEl, points, opts) => svgEl;\n", encoding="utf-8")
    assert len(_warns(_rule().check(_ctx(tmp_path)))) == 2


def test_same_name_different_first_arg_does_not_warn(tmp_path):
    """The kit contract is `renderX(svgEl, ...)`. A coincidental same-named
    function with a different first arg is NOT a reimplementation."""
    (tmp_path / "game.js").write_text(
        "function renderBars(ctx, data) { return ctx; }\n", encoding="utf-8")
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_aact_class_and_resolver_warn(tmp_path):
    (tmp_path / "loc.py").write_text(
        "class AACTLocation:\n    pass\n", encoding="utf-8")
    (tmp_path / "res.py").write_text(
        "def resolve_aact_location(spec):\n    return spec\n", encoding="utf-8")
    assert len(_warns(_rule().check(_ctx(tmp_path)))) == 2


def test_file_referencing_the_kit_is_exempt(tmp_path):
    """If the file imports/mentions the kit, it's USING it, not reimplementing."""
    (tmp_path / "use.js").write_text(
        "import { renderForest } from 'chartkit';\n"
        "function renderForest(svgEl, studies, opts) { return svgEl; }\n",
        encoding="utf-8",
    )
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_aact_user_importing_kit_is_exempt(tmp_path):
    (tmp_path / "u.py").write_text(
        "from aact_kit import resolve_aact_location\n"
        "def resolve_aact_location(spec):\n    return spec\n",
        encoding="utf-8",
    )
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_kit_owned_path_is_exempt(tmp_path):
    """The kit's own source defines these legitimately -- never flag it."""
    d = tmp_path / "e156-chart-kit"
    d.mkdir()
    (d / "chartkit.js").write_text(
        "function renderForest(svgEl, studies, opts) { return svgEl; }\n",
        encoding="utf-8")
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_skip_marker_suppresses(tmp_path):
    (tmp_path / "bespoke.js").write_text(
        "// sentinel:skip-file\n"
        "function renderForest(svgEl, studies, opts) { return svgEl; }\n",
        encoding="utf-8",
    )
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_no_primitive_is_inert(tmp_path):
    (tmp_path / "plain.py").write_text(
        "def add(a, b):\n    return a + b\n", encoding="utf-8")
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_excluded_dirs_are_skipped(tmp_path):
    for sub in ("node_modules", "vendor", "tests"):
        d = tmp_path / sub
        d.mkdir()
        (d / "x.js").write_text(
            "function renderForest(svgEl, s, o) { return svgEl; }\n", encoding="utf-8")
    assert _warns(_rule().check(_ctx(tmp_path))) == []
