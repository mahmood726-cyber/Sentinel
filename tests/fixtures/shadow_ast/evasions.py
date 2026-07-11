"""GROUND TRUTH: real vulnerabilities that EVADE the regex rules but that the
AST matchers catch. Every hit in this file is a TRUE POSITIVE. This file lives
under tests/fixtures/ so the live Sentinel scan excludes it; the shadow
measurement scans it explicitly.

NOTE: no `sentinel:skip-file` marker here on purpose — the measurement must see
these lines. tests/fixtures/ is already excluded from real pushes.
"""
import builtins
import pickle as _pk
from pickle import loads as _loads
import yaml as _y


def evade_eval_via_getattr(user_input):
    # regex `unsafe_eval_exec` cannot see this: the token "eval" never appears
    # adjacent to "(" — it is assembled at runtime.
    e = "ev" + "al"
    return getattr(builtins, e)(user_input)          # TP: getattr-indirection


def evade_exec_via_builtins_attr(code):
    return builtins.exec(code)                        # TP: builtins-attr


def evade_pickle_via_alias(blob):
    return _pk.loads(blob)                            # TP: pickle-alias


def evade_pickle_via_from_import(blob):
    return _loads(blob)                               # TP: pickle-from-import


def evade_yaml_multiline(text):
    # Loader on a separate line — the single-line regex negative-lookahead
    # for "Safe" is on the `yaml.load(` line, which has no Loader token.
    return _y.load(
        text,
        Loader=_y.Loader,
    )                                                 # TP: yaml-load (unsafe)


# Split-string AWS-shaped key (NOT a real credential): no single source LINE
# contains the whole token, so the line-scanning regex misses it; the AST
# matcher folds the `+` and matches. TP: split-string.
LEAKED = "AKIA" + "ZZ7QRSTUVWX9YABC"
