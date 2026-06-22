"""Unit tests for the LLM-triage precision layer (sentinel.triage).

All tests are fully offline: the model call is injected (`llm_call`) and the
backend auto-detector is monkeypatched. The invariants under test are the
non-negotiable ones: fail-closed on every error path, and downgrade-only
(BLOCK -> WARN, never delete, never touch WARN/INFO).
"""
from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path

import pytest

from sentinel.core import Severity, Verdict
from sentinel import triage as t


def _v(rule_id="P0-x", severity=Severity.BLOCK, repo="", file="a.py",
       line=2, detail="bad thing", fix_hint="do better", source="src"):
    return Verdict(rule_id=rule_id, severity=severity, repo=repo, file=file,
                   line=line, detail=detail, fix_hint=fix_hint, source=source,
                   timestamp=datetime(2026, 5, 29))


# --------------------------- _parse_response (fail-closed) ----------------- #
@pytest.mark.parametrize("text,expected_verdict", [
    ('{"verdict":"likely_fp","confidence":0.9,"reason":"guarded"}', "likely_fp"),
    ('here: {"verdict":"downgrade","confidence":0.5,"reason":"x"} ok', "downgrade"),
    ("", "keep"),                          # empty -> keep
    ("no json at all", "keep"),            # no json -> keep
    ("{bad json", "keep"),                 # unparseable -> keep
    ('{"verdict":"nonsense","confidence":1}', "keep"),  # invalid verdict -> keep
])
def test_parse_response_fails_closed(text, expected_verdict):
    verdict, conf, _ = t._parse_response(text)
    assert verdict == expected_verdict
    assert 0.0 <= conf <= 1.0


def test_parse_response_clamps_confidence():
    _, conf, _ = t._parse_response('{"verdict":"keep","confidence":5.0}')
    assert conf == 1.0
    _, conf2, _ = t._parse_response('{"verdict":"keep","confidence":-3}')
    assert conf2 == 0.0


# --------------------------- context extraction --------------------------- #
def test_read_context_marks_target_line(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("\n".join(f"line{i}" for i in range(1, 11)), encoding="utf-8")
    v = _v(file="a.py", line=5)
    ctx = t._read_context(v, tmp_path, context_lines=2)
    assert ">>    5| line5" in ctx
    assert "    3| line3" in ctx and "    7| line7" in ctx
    assert "line8" not in ctx  # outside the +-2 window


def test_read_context_missing_file_returns_none(tmp_path):
    assert t._read_context(_v(file="nope.py"), tmp_path, 5) is None


# --------------------------- triage_verdicts ------------------------------ #
def test_triage_only_blocks_by_default(tmp_path):
    (tmp_path / "a.py").write_text("x=1\ny=2\nz=3\n", encoding="utf-8")
    verdicts = [_v(severity=Severity.BLOCK), _v(severity=Severity.WARN)]
    calls = []

    def fake(prompt):
        calls.append(prompt)
        return '{"verdict":"keep","confidence":0.1,"reason":"r"}'

    res = t.triage_verdicts(verdicts, fake, repo_root=tmp_path)
    assert len(res) == 1                      # WARN skipped
    assert len(calls) == 1
    res_all = t.triage_verdicts(verdicts, fake, repo_root=tmp_path, only_blocks=False)
    assert len(res_all) == 2


def test_triage_fails_closed_on_backend_exception(tmp_path):
    (tmp_path / "a.py").write_text("x=1\ny=2\nz=3\n", encoding="utf-8")

    def boom(prompt):
        raise RuntimeError("api down")

    res = t.triage_verdicts([_v()], boom, repo_root=tmp_path)
    assert res[0].verdict == "keep"
    assert res[0].confidence == 0.0
    assert "triage error" in res[0].reason


def test_triage_missing_context_keeps(tmp_path):
    res = t.triage_verdicts([_v(file="ghost.py")], lambda p: "x", repo_root=tmp_path)
    assert res[0].verdict == "keep"
    assert res[0].confidence == 0.0


# --------------------------- apply_triage (downgrade-only) ---------------- #
def test_apply_downgrades_block_to_warn_above_threshold():
    v = _v(severity=Severity.BLOCK)
    res = [t.TriageResult(v.rule_id, v.file, v.line, "BLOCK", "likely_fp", 0.95, "fp")]
    out = t.apply_triage([v], res, min_confidence=0.8)
    assert out[0].severity == Severity.WARN
    assert "downgraded from BLOCK" in out[0].detail


def test_apply_respects_confidence_threshold():
    v = _v(severity=Severity.BLOCK)
    res = [t.TriageResult(v.rule_id, v.file, v.line, "BLOCK", "likely_fp", 0.5, "fp")]
    out = t.apply_triage([v], res, min_confidence=0.8)
    assert out[0].severity == Severity.BLOCK   # below threshold -> unchanged


def test_apply_never_touches_warn_or_info():
    vw = _v(severity=Severity.WARN)
    # even a likely_fp verdict at high confidence must not demote a WARN further
    res = [t.TriageResult(vw.rule_id, vw.file, vw.line, "WARN", "likely_fp", 1.0, "fp")]
    out = t.apply_triage([vw], res, min_confidence=0.8)
    assert out[0].severity == Severity.WARN


def test_apply_keeps_when_verdict_is_keep():
    v = _v(severity=Severity.BLOCK)
    res = [t.TriageResult(v.rule_id, v.file, v.line, "BLOCK", "keep", 1.0, "real")]
    out = t.apply_triage([v], res, min_confidence=0.8)
    assert out[0].severity == Severity.BLOCK


def test_apply_never_drops_findings():
    vs = [_v(rule_id="A"), _v(rule_id="B"), _v(rule_id="C")]
    res = [t.TriageResult("A", "a.py", 2, "BLOCK", "likely_fp", 1.0, "fp")]
    out = t.apply_triage(vs, res, min_confidence=0.8)
    assert len(out) == 3


# --------------------------- advisory-only (P2-10) ------------------------ #
def test_demoted_verdict_carries_advisory_marker():
    """A downgraded verdict must be machine-detectable as LLM-advisory so the
    Overmind aggregator never counts it as a deterministic WARN."""
    v = _v(severity=Severity.BLOCK, source="lessons.md#x")
    res = [t.TriageResult(v.rule_id, v.file, v.line, "BLOCK", "likely_fp", 0.95, "fp")]
    out = t.apply_triage([v], res, min_confidence=0.8)
    assert t.ADVISORY_MARKER in out[0].source
    assert "lessons.md#x" in out[0].source  # original provenance preserved
    assert "advisory" in out[0].detail.lower()


def test_kept_verdict_has_no_advisory_marker():
    v = _v(severity=Severity.BLOCK, source="lessons.md#x")
    res = [t.TriageResult(v.rule_id, v.file, v.line, "BLOCK", "keep", 1.0, "real")]
    out = t.apply_triage([v], res, min_confidence=0.8)
    assert t.ADVISORY_MARKER not in out[0].source


# --------------------------- load_verdicts_json --------------------------- #
def test_load_verdicts_json_roundtrip(tmp_path):
    v = _v()
    p = tmp_path / "scan.json"
    p.write_text(json.dumps({"verdicts": [v.to_dict()]}), encoding="utf-8")
    loaded = t.load_verdicts_json(p)
    assert len(loaded) == 1
    assert loaded[0].rule_id == v.rule_id
    assert loaded[0].severity == Severity.BLOCK


def test_load_verdicts_json_bare_list(tmp_path):
    p = tmp_path / "scan.json"
    p.write_text(json.dumps([_v().to_dict()]), encoding="utf-8")
    assert len(t.load_verdicts_json(p)) == 1


# --------------------------- detect_backend (no-op path) ------------------ #
def test_detect_backend_none_when_nothing_available(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(t, "_ollama_reachable", lambda: False)
    name, call = t.detect_backend()
    assert name is None and call is None


def test_detect_backend_prefers_ollama_when_reachable(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(t, "_ollama_reachable", lambda: True)
    name, call = t.detect_backend()
    assert name is not None and name.startswith("ollama:")
    assert callable(call)
