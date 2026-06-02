"""Tests for the 1C AI-code-vuln rule pack + rules-index integrity.

- P0-unsafe-eval-exec        : eval/exec of non-literal args
- P1-insecure-deserialization: pickle/marshal load(s), yaml.load w/o Safe loader
- P1-rules-index-integrity   : rules/_index.yaml refs must resolve
"""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule

PLUGINS = Path(__file__).parent.parent.parent / "sentinel" / "rules" / "plugins"


def _rule(name):
    return load_plugin_rule(PLUGINS / name)


def _ctx(p: Path) -> RepoContext:
    return RepoContext(repo_root=p, mode=ScanMode.REPO)


# --- P0-unsafe-eval-exec ----------------------------------------------------

def test_eval_exec_is_block():
    assert _rule("unsafe_eval_exec.py").severity == Severity.BLOCK


def test_eval_exec_fires_on_dynamic(tmp_path):
    (tmp_path / "bad.py").write_text("result = eval(user_input)\nexec(payload)\n", encoding="utf-8")
    assert len(_rule("unsafe_eval_exec.py").check(_ctx(tmp_path))) == 2


def test_eval_exec_ignores_string_literal(tmp_path):
    (tmp_path / "ok.py").write_text('x = eval("1 + 1")\nexec("")\n', encoding="utf-8")
    assert _rule("unsafe_eval_exec.py").check(_ctx(tmp_path)) == []


def test_eval_exec_ignores_literal_eval(tmp_path):
    (tmp_path / "ok.py").write_text("import ast\nv = ast.literal_eval(s)\n", encoding="utf-8")
    assert _rule("unsafe_eval_exec.py").check(_ctx(tmp_path)) == []


# --- P1-insecure-deserialization --------------------------------------------

def test_pickle_loads_fires(tmp_path):
    (tmp_path / "bad.py").write_text("import pickle\no = pickle.loads(blob)\n", encoding="utf-8")
    assert len(_rule("insecure_deserialization.py").check(_ctx(tmp_path))) == 1


def test_yaml_load_unsafe_fires(tmp_path):
    (tmp_path / "bad.py").write_text("import yaml\nc = yaml.load(text)\n", encoding="utf-8")
    assert len(_rule("insecure_deserialization.py").check(_ctx(tmp_path))) == 1


def test_yaml_safe_load_ok(tmp_path):
    (tmp_path / "ok.py").write_text(
        "import yaml\na = yaml.safe_load(t)\nb = yaml.load(t, Loader=yaml.SafeLoader)\n",
        encoding="utf-8",
    )
    assert _rule("insecure_deserialization.py").check(_ctx(tmp_path)) == []


def test_json_loads_ok(tmp_path):
    (tmp_path / "ok.py").write_text("import json\nd = json.loads(t)\n", encoding="utf-8")
    assert _rule("insecure_deserialization.py").check(_ctx(tmp_path)) == []


# --- P1-rules-index-integrity -----------------------------------------------

def _mk_index(tmp_path: Path, ref: str) -> None:
    (tmp_path / "rules").mkdir(exist_ok=True)
    (tmp_path / "rules" / "rules.md").write_text("# Rules\n## Workflow\nbody\n", encoding="utf-8")
    (tmp_path / "AGENTS.md").write_text("# Agents\n", encoding="utf-8")
    (tmp_path / "rules" / "_index.yaml").write_text(
        "always:\n  - AGENTS.md\n"
        "rules:\n  - id: t\n    load:\n      - \"%s\"\n"
        "fallback: []\n" % ref,
        encoding="utf-8",
    )


def test_index_integrity_good_ref(tmp_path):
    _mk_index(tmp_path, "rules.md#Workflow")
    assert _rule("rules_index_integrity.py").check(_ctx(tmp_path)) == []


def test_index_integrity_missing_section(tmp_path):
    _mk_index(tmp_path, "rules.md#Does Not Exist")
    assert len(_rule("rules_index_integrity.py").check(_ctx(tmp_path))) == 1


def test_index_integrity_missing_file(tmp_path):
    _mk_index(tmp_path, "ghost.md#X")
    assert len(_rule("rules_index_integrity.py").check(_ctx(tmp_path))) == 1


def test_index_integrity_noop_without_index(tmp_path):
    assert _rule("rules_index_integrity.py").check(_ctx(tmp_path)) == []
