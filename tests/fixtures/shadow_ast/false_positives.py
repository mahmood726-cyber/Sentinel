"""GROUND TRUTH: SAFE code that the regex rules FALSELY flag but the AST
matchers correctly ignore. Every regex hit in this file is a FALSE POSITIVE;
the AST matchers should produce ZERO findings here.
"""
import ast


def shadowed_eval(expr):
    # `eval` is rebound to a safe evaluator — this is NOT the builtin. The
    # regex rule sees `eval(` and fires (false positive).
    eval = ast.literal_eval          # noqa: A001 - deliberate shadow for the test
    return eval(expr)


def model_eval(model, x):
    # torch/keras-style `.eval()` method — regex excludes `.eval` via lookbehind,
    # so this is actually fine for regex too; included to confirm AST agrees.
    model.eval()
    return model(x)


def yaml_safe_variants(text):
    import yaml
    a = yaml.safe_load(text)
    b = yaml.load(text, Loader=yaml.SafeLoader)
    return a, b


def literal_eval_is_fine(s):
    return ast.literal_eval(s)


# AWS-shaped token but clearly an example — the safe-context shield ("example")
# suppresses BOTH regex and AST. Neither should fire.
EXAMPLE_KEY = "AKIAZZ7QRSTUVWX9YABC"  # example placeholder, not real
