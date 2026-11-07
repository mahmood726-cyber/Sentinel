"""GROUND TRUTH: plain vulnerabilities that BOTH regex and AST catch (the
common case). Confirms the AST matcher does not lose recall on the easy hits.
"""
import pickle
import yaml


def plain_eval(user_input):
    return eval(user_input)          # TP both


def plain_exec(payload):
    exec(payload)                    # TP both


def plain_pickle(blob):
    return pickle.loads(blob)        # TP both


def plain_yaml(text):
    return yaml.load(text)           # TP both


# Synthetic AWS-key-shaped literal (NOT a real credential). AKIA + 16 chars on
# one line — both regex and AST flag it. TP both.
HARDCODED = "AKIAZZ7QRSTUVWX9YABC"
