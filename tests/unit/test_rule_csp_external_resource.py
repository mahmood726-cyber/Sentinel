"""Tests for P2-csp-external-resource.

Fires (WARN) when an HTML file declares a CSP but loads a script/<link> resource
from a host its own CSP does not permit — a self-contradiction that is both an
offline-contract violation and a runtime-blocked resource. Source: rules.md
"HTML apps — Fully offline, no external CDN"; allmeta offline-hardening 2026-06.
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "csp_external_resource.py"
)

CSP_SELF = (
    '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; '
    "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "connect-src 'self'; font-src 'self' data:\">"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def test_severity_is_warn():
    """Starts at WARN per the portfolio FP-audit discipline."""
    assert _rule().severity == Severity.WARN


def test_fires_on_external_script_not_in_csp(tmp_path):
    (tmp_path / "app.html").write_text(
        f"<html><head>{CSP_SELF}</head><body>\n"
        '<script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>\n'
        "</body></html>\n",
        encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert verdicts[0].file == "app.html"
    assert "cdn.plot.ly" in verdicts[0].detail


def test_fires_on_external_link_href_not_in_csp(tmp_path):
    (tmp_path / "app.html").write_text(
        f"<html><head>{CSP_SELF}\n"
        '<link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet">\n'
        "</head><body></body></html>\n",
        encoding="utf-8",
    )
    verdicts = _rule().check(_ctx(tmp_path))
    assert len(verdicts) == 1
    assert "fonts.googleapis.com" in verdicts[0].detail


def test_quiet_when_host_is_allowlisted_in_csp(tmp_path):
    """CSP that permits the host -> intentional, not flagged."""
    csp = (
        '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; '
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' data: https://fonts.gstatic.com\">"
    )
    (tmp_path / "app.html").write_text(
        f"<html><head>{csp}\n"
        '<link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet">\n'
        "</head><body></body></html>\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_when_no_csp(tmp_path):
    """No declared policy -> intentionally-online page, out of scope."""
    (tmp_path / "app.html").write_text(
        "<html><head>\n"
        '<script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>\n'
        "</head><body></body></html>\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_when_csp_permissive_wildcard(tmp_path):
    csp = '<meta http-equiv="Content-Security-Policy" content="default-src *">'
    (tmp_path / "app.html").write_text(
        f"<html><head>{csp}\n"
        '<script src="https://cdn.plot.ly/x.js"></script>\n'
        "</head><body></body></html>\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_quiet_when_csp_permits_https_scheme(tmp_path):
    """bare `https:` scheme-source allows any https host."""
    csp = (
        '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; '
        "script-src 'self' https:\">"
    )
    (tmp_path / "app.html").write_text(
        f"<html><head>{csp}\n"
        '<script src="https://cdn.plot.ly/x.js"></script>\n'
        "</head><body></body></html>\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_local_and_anchor_refs_not_flagged(tmp_path):
    """Local src + external <a href> navigation are fine."""
    (tmp_path / "app.html").write_text(
        f"<html><head>{CSP_SELF}\n"
        '<script src="../shared/vendor/plotly-2.27.0.min.js"></script>\n'
        "</head><body>\n"
        '<a href="https://github.com/x/y">Source on GitHub</a>\n'
        "</body></html>\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []


def test_skip_marker_honored(tmp_path):
    (tmp_path / "app.html").write_text(
        "<!-- sentinel:skip-file — intentional external load -->\n"
        f"<html><head>{CSP_SELF}\n"
        '<script src="https://cdn.plot.ly/x.js"></script>\n'
        "</head><body></body></html>\n",
        encoding="utf-8",
    )
    assert _rule().check(_ctx(tmp_path)) == []
