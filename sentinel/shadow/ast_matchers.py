"""AST-based shadow matchers for the three "hot" AI-code-vuln rules.

Each matcher parses Python source with the stdlib `ast` module and walks the
tree, so it is immune to the text-level tricks that defeat the regex rules:
  * string/comment blanking games,
  * `import ... as alias` renaming the dangerous module,
  * multi-line calls (regex rules match a single line),
  * builtin indirection: `getattr(builtins, "ev"+"al")(...)`,
  * split-string secrets: `"AKIA" + "IOSFODNN7EXAMPLE0"`.

These matchers are DELIBERATELY not Sentinel rule plugins — they are not in
`sentinel/rules/`, are not in the registry, and never emit a BLOCK into the
push path. They return plain `ShadowFinding`s for the measurement harness.

The `leaked_secret` matcher reuses the EXACT credential patterns and the
safe-context shield from the enforcing plugin (`sentinel.rules.plugins.
leaked_secret`) so that any regex-vs-AST difference is attributable to the
matching MECHANISM (line-scan vs constant-folding), not to a different
pattern set.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import List, Optional

from sentinel.rules.plugins import leaked_secret as _ls

# Builtins that execute arbitrary code / import machinery when reached
# indirectly. `getattr(x, "eval")(...)` and `builtins.exec(...)` are the
# canonical evasions the regex `unsafe_eval_exec` rule cannot see.
_DANGEROUS_BUILTINS = frozenset({"eval", "exec"})
_BUILTINS_OBJECTS = frozenset({"builtins", "__builtins__"})

# Module names whose load/loads execute arbitrary code on crafted input.
_PICKLE_MODULES = frozenset({"pickle", "cpickle", "cPickle", "_pickle",
                             "marshal", "dill", "shelve"})
_PICKLE_LOADERS = frozenset({"load", "loads"})


@dataclass(frozen=True)
class ShadowFinding:
    """A single AST-matcher hit. `kind` is a short machine tag for grouping
    (e.g. 'eval-name', 'getattr-indirection', 'pickle-alias', 'split-string').
    """
    rule_id: str
    file: str
    line: int
    detail: str
    kind: str


# ── shared static-evaluation helpers ─────────────────────────────────


def _static_str(node: ast.AST) -> Optional[str]:
    """Return the string value of `node` if it is a STATIC string expression
    (constant, `+`-concatenation of constants, f-string with no interpolation,
    or implicit adjacency — which `ast` already merges). Return None if the
    value depends on anything computed at runtime."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_str(node.left)
        right = _static_str(node.right)
        if left is not None and right is not None:
            return left + right
        return None
    if isinstance(node, ast.JoinedStr):
        # f-string: static ONLY if every part is a literal (no FormattedValue).
        parts: List[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                return None
        return "".join(parts)
    return None


def _is_static_arg(node: ast.AST) -> bool:
    """True if a call argument is a compile-time constant (any type), so
    eval/exec on it is not a dynamic-code sink."""
    if isinstance(node, ast.Constant):
        return True
    # A `+` / f-string that folds to a static string is still constant.
    return _static_str(node) is not None


def _parse(source: str) -> Optional[ast.AST]:
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError):
        return None


# ── 1. unsafe eval / exec ────────────────────────────────────────────


def _shadowed_names(tree: ast.AST) -> set[str]:
    """Names rebound somewhere in the module that would make a bare
    `eval(...)` / `exec(...)` NOT the builtin — assignments, defs, params,
    imports-as, for-targets, with-as. Conservative: any binding of the name
    anywhere suppresses the Name-based match (precision over recall)."""
    bound: set[str] = set()

    def _add_target(t: ast.AST) -> None:
        if isinstance(t, ast.Name):
            bound.add(t.id)
        elif isinstance(t, (ast.Tuple, ast.List)):
            for e in t.elts:
                _add_target(e)

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                _add_target(tgt)
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign, ast.NamedExpr)):
            _add_target(node.target)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            _add_target(node.target)
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            _add_target(node.optional_vars)
    # function/lambda parameters
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            a = node.args
            for arg in [*a.posonlyargs, *a.args, *a.kwonlyargs,
                        a.vararg, a.kwarg]:
                if arg is not None:
                    bound.add(arg.arg)
    return bound


def ast_unsafe_eval_exec(source: str, filename: str) -> List[ShadowFinding]:
    """AST analogue of P0-unsafe-eval-exec. Fires on:
      * bare `eval`/`exec` builtin call with a non-constant arg,
      * `builtins.eval(...)` / `__builtins__.exec(...)` attribute calls,
      * `getattr(obj, "eval")(...)` and `getattr(builtins, <dynamic>)(...)`
        indirection (the documented regex evasion).
    Skips the match when the name is locally rebound (shadowed)."""
    tree = _parse(source)
    if tree is None:
        return []
    shadowed = _shadowed_names(tree)
    out: List[ShadowFinding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        first = node.args[0] if node.args else None

        # (a) bare eval/exec Name call
        if isinstance(func, ast.Name) and func.id in _DANGEROUS_BUILTINS:
            if func.id in shadowed:
                continue  # rebound → not the builtin
            if first is not None and _is_static_arg(first):
                continue  # pure literal → safe
            out.append(ShadowFinding(
                rule_id="P0-unsafe-eval-exec", file=filename, line=node.lineno,
                detail=f"`{func.id}(...)` builtin call on a non-literal argument (AST)",
                kind="eval-name",
            ))
            continue

        # (b) builtins.eval / __builtins__.exec attribute call
        if isinstance(func, ast.Attribute) and func.attr in _DANGEROUS_BUILTINS:
            base = func.value
            if isinstance(base, ast.Name) and base.id in _BUILTINS_OBJECTS:
                out.append(ShadowFinding(
                    rule_id="P0-unsafe-eval-exec", file=filename, line=node.lineno,
                    detail=f"`{base.id}.{func.attr}(...)` builtin-module attribute call (AST; regex misses attribute form)",
                    kind="builtins-attr",
                ))
            continue

        # (c) getattr(...)(...) indirection — the func being CALLED is itself a
        #     getattr() whose attribute names a dangerous builtin, or whose
        #     object is the builtins module (dynamic attr → cannot prove safe).
        if isinstance(func, ast.Call) and isinstance(func.func, ast.Name) \
                and func.func.id == "getattr" and len(func.args) >= 2:
            obj, attr = func.args[0], func.args[1]
            attr_val = _static_str(attr)
            obj_is_builtins = isinstance(obj, ast.Name) and obj.id in _BUILTINS_OBJECTS
            if (attr_val in _DANGEROUS_BUILTINS) or obj_is_builtins:
                shown = attr_val if attr_val is not None else "<dynamic>"
                out.append(ShadowFinding(
                    rule_id="P0-unsafe-eval-exec", file=filename, line=node.lineno,
                    detail=f"getattr(...) indirection to builtin '{shown}' then called (AST; defeats string-split/alias evasion)",
                    kind="getattr-indirection",
                ))
    return out


# ── 2. insecure deserialization ──────────────────────────────────────


def _yaml_call_is_safe(node: ast.Call) -> bool:
    """True if a `yaml.load(...)` call carries a Safe loader keyword."""
    for kw in node.keywords:
        if kw.arg == "Loader":
            name = _attr_tail(kw.value)
            if name and "safe" in name.lower():
                return True
    return False


def _attr_tail(node: ast.AST) -> Optional[str]:
    """Rightmost identifier of a Name/Attribute chain (e.g. yaml.SafeLoader
    → 'SafeLoader'). None for anything else."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def ast_insecure_deserialization(source: str, filename: str) -> List[ShadowFinding]:
    """AST analogue of P1-insecure-deserialization. Resolves import aliases and
    `from x import loads`, and inspects `yaml.load` keyword args across line
    breaks — all of which the single-line regex misses."""
    tree = _parse(source)
    if tree is None:
        return []

    # alias → canonical module ; and bare loader names imported directly.
    pickle_aliases: dict[str, str] = {}
    yaml_aliases: set[str] = set()
    bare_pickle_loaders: set[str] = set()   # names bound via `from pickle import loads`
    bare_yaml_load: set[str] = set()        # names bound via `from yaml import load`

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name
                local = alias.asname or alias.name.split(".")[0]
                if mod in _PICKLE_MODULES or mod.split(".")[0] in _PICKLE_MODULES:
                    pickle_aliases[local] = mod
                elif mod.split(".")[0] == "yaml":
                    yaml_aliases.add(local)
        elif isinstance(node, ast.ImportFrom):
            base = (node.module or "").split(".")[0]
            if base in _PICKLE_MODULES:
                for alias in node.names:
                    if alias.name in _PICKLE_LOADERS:
                        bare_pickle_loaders.add(alias.asname or alias.name)
            elif base == "yaml":
                for alias in node.names:
                    if alias.name == "load":
                        bare_yaml_load.add(alias.asname or alias.name)

    out: List[ShadowFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func

        # module.load / module.loads via alias
        if isinstance(func, ast.Attribute) and func.attr in _PICKLE_LOADERS:
            base = func.value
            if isinstance(base, ast.Name) and base.id in pickle_aliases:
                out.append(ShadowFinding(
                    rule_id="P1-insecure-deserialization", file=filename, line=node.lineno,
                    detail=f"{base.id}.{func.attr}(...) -> {pickle_aliases[base.id]} deserialization (AST resolves alias)",
                    kind="pickle-alias",
                ))
                continue

        # bare loads(...) from `from pickle import loads`
        if isinstance(func, ast.Name) and func.id in bare_pickle_loaders:
            out.append(ShadowFinding(
                rule_id="P1-insecure-deserialization", file=filename, line=node.lineno,
                detail=f"bare {func.id}(...) imported from a pickle/marshal module (AST; regex only matches `module.loads`)",
                kind="pickle-from-import",
            ))
            continue

        # yaml.load(...) without a Safe loader (alias-aware, multi-line safe)
        if isinstance(func, ast.Attribute) and func.attr == "load":
            base = func.value
            if isinstance(base, ast.Name) and base.id in yaml_aliases:
                if not _yaml_call_is_safe(node):
                    out.append(ShadowFinding(
                        rule_id="P1-insecure-deserialization", file=filename, line=node.lineno,
                        detail=f"{base.id}.load(...) without a Safe loader (AST inspects Loader= across lines)",
                        kind="yaml-load",
                    ))
                continue

        # bare load(...) from `from yaml import load`
        if isinstance(func, ast.Name) and func.id in bare_yaml_load:
            if not _yaml_call_is_safe(node):
                out.append(ShadowFinding(
                    rule_id="P1-insecure-deserialization", file=filename, line=node.lineno,
                    detail=f"bare {func.id}(...) imported from yaml without a Safe loader (AST)",
                    kind="yaml-from-import",
                ))
    return out


# ── 3. leaked secret (Python string literals) ────────────────────────


def ast_leaked_secret(source: str, filename: str) -> List[ShadowFinding]:
    """AST analogue of P1-leaked-secret, Python-only. Walks string-valued
    expressions — including `+`-concatenations and f-strings — and matches the
    plugin's exact credential patterns on the RECONSTRUCTED value. This catches
    split-string secrets (`"AKIA" + "…"`) that the line-scanning regex misses.

    Non-Python files are out of scope for the AST matcher; the regex rule
    remains the matcher for those (see the report)."""
    tree = _parse(source)
    if tree is None:
        return []
    src_lines = source.splitlines()
    out: List[ShadowFinding] = []
    seen: set[tuple[int, str]] = set()

    for node in ast.walk(tree):
        value = _static_str(node)
        if value is None or len(value) < 16:
            continue
        # Only bother for nodes that actually fold multiple pieces OR are a
        # lone constant; either way we test the reconstructed value.
        line = getattr(node, "lineno", 0)
        for name, pat in _ls._PATTERNS:
            m = pat.search(value)
            if not m:
                continue
            # Same safe-context shield as the plugin, applied to the source line.
            src_line = src_lines[line - 1] if 0 < line <= len(src_lines) else ""
            if _ls.SAFE_CONTEXT_WORDS.search(src_line):
                continue
            key = (line, name)
            if key in seen:
                continue
            seen.add(key)
            is_split = not isinstance(node, ast.Constant)
            preview = m.group(0)
            if len(preview) > 12:
                preview = preview[:6] + "..." + preview[-4:]
            out.append(ShadowFinding(
                rule_id="P1-leaked-secret", file=filename, line=line,
                detail=f"possible {name} in reconstructed string ({preview})"
                       + (" [split/concatenated — regex misses]" if is_split else ""),
                kind="split-string" if is_split else "literal",
            ))
    return out
