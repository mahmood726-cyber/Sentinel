# sentinel:skip-file — fixtures contain example fabricated DOI strings.
"""Tests for P0-citation-resolution.

The rule is offline and cache-driven: it BLOCKs a capsule DOI only when a
committed doi-cache.json marks it "unresolved". No cache -> inert.
"""
from __future__ import annotations

import json
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "citation_resolution.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def _cache(tmp_path: Path, mapping: dict) -> None:
    (tmp_path / "doi-cache.json").write_text(json.dumps(mapping), encoding="utf-8")


def test_no_cache_is_inert(tmp_path):
    (tmp_path / "refs.md").write_text("doi: 10.9999/invented.x\n", encoding="utf-8")
    assert _rule().check(_ctx(tmp_path)) == []


def test_unresolved_doi_blocks(tmp_path):
    (tmp_path / "refs.md").write_text("doi: 10.9999/invented.x\n", encoding="utf-8")
    _cache(tmp_path, {"10.9999/invented.x": {"status": "unresolved", "http_status": 404}})
    blocks = [v for v in _rule().check(_ctx(tmp_path)) if v.severity == Severity.BLOCK]
    assert len(blocks) == 1
    assert "did not resolve" in blocks[0].detail


def test_resolved_doi_clean(tmp_path):
    (tmp_path / "refs.md").write_text("doi: 10.1136/bmj.n2387\n", encoding="utf-8")
    _cache(tmp_path, {"10.1136/bmj.n2387": {"status": "resolved", "http_status": 200}})
    assert _rule().check(_ctx(tmp_path)) == []


def test_unknown_status_does_not_block(tmp_path):
    # paywalled / network-error DOIs are recorded "unknown" and must not block.
    (tmp_path / "refs.md").write_text("doi: 10.5555/paywalled.x\n", encoding="utf-8")
    _cache(tmp_path, {"10.5555/paywalled.x": {"status": "unknown", "http_status": 403}})
    assert _rule().check(_ctx(tmp_path)) == []


def test_skip_marker_file_ignored(tmp_path):
    (tmp_path / "fix.md").write_text(
        "sentinel:skip-file\ndoi: 10.9999/invented.x\n", encoding="utf-8"
    )
    _cache(tmp_path, {"10.9999/invented.x": {"status": "unresolved", "http_status": 404}})
    assert _rule().check(_ctx(tmp_path)) == []


def test_malformed_doi_not_resolution_concern(tmp_path):
    # A 3-digit-registrant DOI is malformed (citation_cascade's BLOCK); even if
    # the cache somehow lists it, resolution only considers well-formed DOIs.
    (tmp_path / "refs.md").write_text("doi: 10.999/x\n", encoding="utf-8")
    _cache(tmp_path, {"10.999/x": {"status": "unresolved", "http_status": 404}})
    assert _rule().check(_ctx(tmp_path)) == []
