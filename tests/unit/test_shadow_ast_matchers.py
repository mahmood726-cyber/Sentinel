"""Tests for the shadow-mode AST matchers (sentinel/shadow/ast_matchers.py).

These prove (a) the AST matcher matches the regex rule on the ordinary cases,
(b) it CATCHES the documented regex-evasion cases the regex rule misses, and
(c) it AVOIDS false positives the regex rule fires on. Shadow-only: none of
this is in the registry or the push path.
"""
from __future__ import annotations

from sentinel.shadow.ast_matchers import (
    ast_insecure_deserialization,
    ast_leaked_secret,
    ast_unsafe_eval_exec,
)


def _lines(findings):
    return sorted(f.line for f in findings)


def _kinds(findings):
    return sorted(f.kind for f in findings)


# ── unsafe eval / exec ───────────────────────────────────────────────


def test_eval_exec_fires_on_dynamic():
    src = "result = eval(user_input)\nexec(payload)\n"
    assert len(ast_unsafe_eval_exec(src, "f.py")) == 2


def test_eval_ignores_string_literal():
    assert ast_unsafe_eval_exec('x = eval("1 + 1")\nexec("")\n', "f.py") == []


def test_eval_ignores_folded_literal():
    # "a" + "b" folds to a constant → safe, like the regex rule treats it.
    assert ast_unsafe_eval_exec('eval("a" + "b")\n', "f.py") == []


def test_eval_ignores_literal_eval_attribute():
    assert ast_unsafe_eval_exec("import ast\nv = ast.literal_eval(s)\n", "f.py") == []


def test_eval_ignores_shadowed_name():
    # `eval` rebound to a safe callable → not the builtin. Regex FALSELY fires.
    src = "eval = safe_evaluator\nr = eval(expr)\n"
    assert ast_unsafe_eval_exec(src, "f.py") == []


def test_eval_ignores_method_named_eval():
    # obj.eval(x) is a method, not the builtin. AST does not fire.
    assert ast_unsafe_eval_exec("model.eval(x)\nself.eval(data)\n", "f.py") == []


# ---- the documented regex evasions the regex rule MISSES ----

def test_evasion_getattr_string_split():
    # From the benchmark: e = "ev"+"al"; getattr(builtins, e)(...)
    src = (
        "import builtins\n"
        'e = "ev" + "al"\n'
        "getattr(builtins, e)(user_input)\n"
    )
    findings = ast_unsafe_eval_exec(src, "f.py")
    assert len(findings) == 1
    assert findings[0].kind == "getattr-indirection"


def test_evasion_getattr_constant_attr():
    src = 'getattr(some_obj, "eval")(payload)\n'
    findings = ast_unsafe_eval_exec(src, "f.py")
    assert len(findings) == 1
    assert findings[0].kind == "getattr-indirection"


def test_evasion_builtins_attribute():
    src = "import builtins\nbuiltins.exec(code)\n"
    findings = ast_unsafe_eval_exec(src, "f.py")
    assert len(findings) == 1
    assert findings[0].kind == "builtins-attr"


# ── insecure deserialization ─────────────────────────────────────────


def test_pickle_loads_fires():
    assert len(ast_insecure_deserialization("import pickle\no = pickle.loads(b)\n", "f.py")) == 1


def test_yaml_load_unsafe_fires():
    assert len(ast_insecure_deserialization("import yaml\nc = yaml.load(t)\n", "f.py")) == 1


def test_yaml_safe_load_ok():
    src = (
        "import yaml\n"
        "a = yaml.safe_load(t)\n"
        "b = yaml.load(t, Loader=yaml.SafeLoader)\n"
    )
    assert ast_insecure_deserialization(src, "f.py") == []


def test_json_loads_ok():
    assert ast_insecure_deserialization("import json\nd = json.loads(t)\n", "f.py") == []


# ---- evasions the single-line/exact-name regex MISSES ----

def test_evasion_pickle_import_alias():
    # `import pickle as p` — regex only matches literal `pickle.loads`.
    src = "import pickle as p\no = p.loads(blob)\n"
    findings = ast_insecure_deserialization(src, "f.py")
    assert len(findings) == 1
    assert findings[0].kind == "pickle-alias"


def test_evasion_from_pickle_import_loads():
    # `from pickle import loads; loads(x)` — no `pickle.` prefix on the call.
    src = "from pickle import loads\no = loads(blob)\n"
    findings = ast_insecure_deserialization(src, "f.py")
    assert len(findings) == 1
    assert findings[0].kind == "pickle-from-import"


def test_evasion_yaml_load_multiline_loader():
    # Loader on the next line — the single-line regex negative-lookahead misses
    # the Loader token and would fire; but with an UNSAFE loader it SHOULD fire,
    # and with a SAFE loader on the next line it should NOT.
    unsafe = "import yaml\nyaml.load(\n    text,\n    Loader=yaml.Loader,\n)\n"
    safe = "import yaml\nyaml.load(\n    text,\n    Loader=yaml.SafeLoader,\n)\n"
    assert len(ast_insecure_deserialization(unsafe, "f.py")) == 1
    assert ast_insecure_deserialization(safe, "f.py") == []


# ── leaked secret (Python literals) ──────────────────────────────────


def test_secret_plain_literal_fires():
    # AKIA + exactly 16 [0-9A-Z]; no "example/placeholder" word on the line.
    src = 'KEY = "AKIAIOSFODNN7REALKEY"\n'
    findings = ast_leaked_secret(src, "f.py")
    assert len(findings) == 1


def test_secret_split_string_fires_ast_only():
    # Split so no single source line contains the whole key → regex misses.
    src = 'KEY = "AKIA" + "REALKEY0SFODNN71"\n'
    findings = ast_leaked_secret(src, "f.py")
    assert len(findings) == 1
    assert findings[0].kind == "split-string"


def test_secret_respects_example_shield():
    src = 'KEY = "AKIAIOSFODNN7EXAMPLE0"  # example only\n'
    assert ast_leaked_secret(src, "f.py") == []


def test_secret_ignores_short_strings():
    assert ast_leaked_secret('x = "short"\n', "f.py") == []


# ── robustness ───────────────────────────────────────────────────────


def test_syntax_error_source_returns_empty():
    bad = "def (:\n  eval(x\n"
    assert ast_unsafe_eval_exec(bad, "f.py") == []
    assert ast_insecure_deserialization(bad, "f.py") == []
    assert ast_leaked_secret(bad, "f.py") == []
