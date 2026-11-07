# sentinel:skip-file — docstring + patterns contain the bad forms by design.
"""P1-insecure-deserialization: WARN on deserializers that execute arbitrary
code on crafted input — `pickle.load(s)`, `cPickle.load(s)`, `marshal.loads`,
and `yaml.load(...)` without a Safe loader. A frequent AI-generated-code
failure mode (agents pick pickle/yaml.load for convenience without considering
untrusted input).

    pickle.loads(blob)                 # BAD — RCE on crafted pickle
    yaml.load(text)                    # BAD — full constructor; use safe_load
    yaml.load(text, Loader=Loader)     # BAD — non-Safe loader
    yaml.safe_load(text)               # OK
    yaml.load(text, Loader=SafeLoader) # OK
    json.loads(text)                   # OK

WARN, not BLOCK: deserialization of *trusted* local data is sometimes
legitimate (e.g. a model cache the same program wrote). Surfaces the risk;
suppress per-line with the skip marker when the source is provably trusted.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import List

from sentinel.core import RepoContext, Severity, Verdict
from sentinel.io.git_files import iter_repo_files
from sentinel.io.population import Population
from sentinel.io.skip_marker import has_skip_marker, line_is_suppressed

ID = "P1-insecure-deserialization"
SEVERITY = Severity.WARN
SOURCE = "lessons.md#code-quality (deserializing untrusted input is an RCE sink)"
SCOPE = "repo"

# Population: PRESENT -- tracked AND untracked-not-ignored. This is a
# CORRECTNESS rule: the defect it finds runs when someone runs the file,
# whether or not git is tracking it. Migrated 2026-08-30; counts from
# before that date were taken over the tracked set only and are NOT
# comparable with counts after it.
POPULATION = Population.PRESENT

MAX_FILE_BYTES = 5_000_000
PY_EXCLUDE_DIRS = (".venv", "venv", "__pycache__", "build", "dist",
                   ".tox", ".pytest_cache", "node_modules")

# pickle/cPickle/marshal load(s) — always unsafe on untrusted input.
_PICKLE_RE = re.compile(r"(?<![\w.])(?:c?[Pp]ickle|marshal)\.loads?\(")
# yaml.load( ... )  where the call does NOT carry a Safe loader. Single-line
# negative lookahead: no "safe_load", no "SafeLoader", no "Loader=...Safe".
_YAML_RE = re.compile(r"(?<![\w.])yaml\.load\((?![^)\n]*[Ss]afe)")

_LINE_COMMENT_RE = re.compile(r"#[^\n]*")
_STRING_RE = re.compile(
    r"'''(?:\\.|.)*?'''|\"\"\"(?:\\.|.)*?\"\"\""
    r"|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"",
    re.DOTALL,
)


def _strip_noise(text: str) -> str:
    def _ws(m):
        return " " * (m.end() - m.start())
    return _LINE_COMMENT_RE.sub(_ws, _STRING_RE.sub(_ws, text))


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    root = ctx.repo_root
    for path in iter_repo_files(root, "*.py", PY_EXCLUDE_DIRS, population=POPULATION):
        if has_skip_marker(path):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "pickle" not in text and "marshal" not in text and "yaml.load" not in text:
            continue
        stripped = _strip_noise(text)
        lines = text.splitlines()
        rel = path.relative_to(root).as_posix()
        for rx, what, hint in (
            (_PICKLE_RE, "pickle/marshal load", "use json for data interchange; only unpickle data your own process wrote"),
            (_YAML_RE, "yaml.load without a Safe loader", "use yaml.safe_load(...) (or Loader=yaml.SafeLoader)"),
        ):
            for m in rx.finditer(stripped):
                line_no = _line_of(text, m.start())
                cur = lines[line_no - 1] if line_no - 1 < len(lines) else ""
                prv = lines[line_no - 2] if line_no - 2 >= 0 else ""
                if line_is_suppressed(cur, prv, ID):
                    continue
                verdicts.append(Verdict(
                    rule_id=ID,
                    severity=SEVERITY,
                    repo=str(root),
                    file=rel,
                    line=line_no,
                    detail=f"insecure deserialization ({what}) — executes arbitrary code on crafted input",
                    fix_hint=hint,
                    source=SOURCE,
                    timestamp=now,
                ))
    return verdicts
