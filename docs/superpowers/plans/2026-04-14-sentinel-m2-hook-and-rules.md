# Sentinel M2 — Pre-Push Hook + Rules 4–9 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the pre-push git-hook installer (idempotent, chaining) + 6 more rules (`P0-claude-config-committed`, `P0-hardcoded-local-path`, `P1-unpopulated-placeholder`, `P1-silent-failure-sentinel`, `P1-script-in-template-literal`, `P0-workbook-rewrite-touched`), and deploy the hook to 5 high-stakes repos. Catch at least one real BLOCK event in the wild.

**Architecture:** Hook installer lives in `sentinel/hook/`. The installed hook is a minimal shell script that invokes `python -m sentinel scan --repo $(pwd) --trigger pre-push` and chains to any pre-existing hook on exit 0. Rules 4–8 are YAML pattern matchers (consumes M1's YAML loader). Rule 9 is a Python plugin that parses `git diff` output for workbook-protection enforcement.

**Tech Stack:** Python 3.13 (Windows-first, cross-platform hook), PyYAML, pytest, `subprocess` for `git diff`. No new deps.

**Non-goals for M2:** Dashboard (M3), nightly cron sweep (M3), rule 10 (M3), portfolio-wide deployment across all 472 repos (M3).

**Prereqs:** M1 complete (tag `m1-rule-engine`). Branch: create `m2/hook-and-rules` off `main` after M1 is merged into `main`, OR continue on `m1/rule-engine` if M1 hasn't merged yet. Default: `m2/hook-and-rules` off the current M1 branch.

---

## File Structure

```
C:\Sentinel\
  sentinel/
    hook/                              # NEW in M2
      __init__.py
      installer.py                     # install / uninstall / chain logic
      payload.py                       # Shell-script content emitted into .git/hooks/pre-push
    rules/
      yaml/
        P0-placeholder-hmac.yaml       # existing
        P0-claude-config-committed.yaml  # Rule 4
        P0-hardcoded-local-path.yaml     # Rule 5
        P1-unpopulated-placeholder.yaml  # Rule 6
        P1-silent-failure-sentinel.yaml  # Rule 7
        P1-script-in-template-literal.yaml  # Rule 8
      plugins/
        path_not_exist.py              # existing
        registry_drift.py              # existing
        workbook_rewrite_touched.py    # Rule 9 — git diff parser
    cli/
      __main__.py                      # MODIFY — register install-hook subcommand
      install_hook.py                  # NEW — install-hook subcommand
  tests/
    unit/
      test_hook_installer.py           # NEW
      test_cli_install_hook.py         # NEW
      test_rule_claude_config.py       # NEW
      test_rule_hardcoded_local_path.py  # NEW
      test_rule_unpopulated_placeholder.py  # NEW
      test_rule_silent_failure_sentinel.py  # NEW
      test_rule_script_in_template.py  # NEW
      test_rule_workbook_rewrite_touched.py  # NEW
    fixtures/
      repos/
        claude_config_BAD/.claude/settings.json  # Rule 4 fixture
        claude_config_GOOD/.gitignore
        hardcoded_path_BAD/dashboard.html        # Rule 5
        hardcoded_path_GOOD/dashboard.html
        placeholder_BAD/readme.md                # Rule 6
        placeholder_GOOD/readme.md
        silent_failure_BAD/module.py             # Rule 7
        silent_failure_GOOD/module.py
        script_template_BAD/index.html           # Rule 8
        script_template_GOOD/index.html
      workbook_fixtures/
        workbook_touched_diff.patch              # Rule 9 — sample diff touching YOUR REWRITE
        workbook_clean_diff.patch                # Rule 9 — sample diff NOT touching YOUR REWRITE
    regression/
      test_hook_chaining_idempotent.py # NEW — the 4th non-regression guarantee
```

---

## Task 1: Hook installer core

**Files:**
- Create: `C:\Sentinel\sentinel\hook\__init__.py`
- Create: `C:\Sentinel\sentinel\hook\installer.py`
- Create: `C:\Sentinel\sentinel\hook\payload.py`
- Create: `C:\Sentinel\tests\unit\test_hook_installer.py`

- [ ] **Step 1: Write failing test** `tests/unit/test_hook_installer.py`:

```python
from pathlib import Path
import stat
import pytest

from sentinel.hook.installer import (
    install_hook,
    uninstall_hook,
    is_sentinel_hook,
    HookInstallError,
)


def _make_git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git" / "hooks").mkdir(parents=True)
    return repo


def test_install_hook_creates_sentinel_marker(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    install_hook(repo)
    hook = repo / ".git" / "hooks" / "pre-push"
    assert hook.exists()
    assert is_sentinel_hook(hook)


def test_install_hook_idempotent(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    install_hook(repo)
    first = (repo / ".git" / "hooks" / "pre-push").read_text(encoding="utf-8")
    install_hook(repo)
    second = (repo / ".git" / "hooks" / "pre-push").read_text(encoding="utf-8")
    assert first == second


def test_install_hook_chains_existing_hook(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-push"
    existing = "#!/bin/sh\necho existing-hook\n"
    hook.write_text(existing, encoding="utf-8")
    install_hook(repo)
    backup = repo / ".git" / "hooks" / "pre-push.sentinel-backup"
    assert backup.exists()
    assert backup.read_text(encoding="utf-8") == existing
    new = hook.read_text(encoding="utf-8")
    assert "sentinel" in new.lower()
    assert "pre-push.sentinel-backup" in new


def test_install_hook_double_install_preserves_single_backup(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-push"
    hook.write_text("#!/bin/sh\necho original\n", encoding="utf-8")
    install_hook(repo)
    install_hook(repo)
    backup = repo / ".git" / "hooks" / "pre-push.sentinel-backup"
    assert backup.read_text(encoding="utf-8") == "#!/bin/sh\necho original\n"
    # Not two levels of backup:
    assert not (repo / ".git" / "hooks" / "pre-push.sentinel-backup.sentinel-backup").exists()


def test_install_hook_raises_on_non_git_dir(tmp_path: Path):
    with pytest.raises(HookInstallError, match="not a git repository"):
        install_hook(tmp_path)


def test_uninstall_restores_backup(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-push"
    original = "#!/bin/sh\necho original\n"
    hook.write_text(original, encoding="utf-8")
    install_hook(repo)
    uninstall_hook(repo)
    assert hook.read_text(encoding="utf-8") == original
    assert not (repo / ".git" / "hooks" / "pre-push.sentinel-backup").exists()


def test_uninstall_removes_hook_when_no_backup(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    install_hook(repo)
    uninstall_hook(repo)
    assert not (repo / ".git" / "hooks" / "pre-push").exists()
```

- [ ] **Step 2:** `python -m pytest tests/unit/test_hook_installer.py -v` → FAIL (ModuleNotFoundError).

- [ ] **Step 3: Write** `sentinel/hook/payload.py`:

```python
"""The shell script that Sentinel installs as .git/hooks/pre-push.

SENTINEL_MARKER is a unique banner that lets us detect whether a hook
file was installed by Sentinel (vs. an unrelated user hook)."""
from __future__ import annotations

SENTINEL_MARKER = "# === SENTINEL PRE-PUSH HOOK (do not edit above this line) ==="

HOOK_SCRIPT = f"""#!/bin/sh
{SENTINEL_MARKER}
# Sentinel runs first; on exit 0 we chain to any prior hook saved as
# pre-push.sentinel-backup. Bypass with SENTINEL_BYPASS=1.

if [ "${{SENTINEL_BYPASS:-0}}" = "1" ]; then
  echo "[Sentinel] bypass requested via SENTINEL_BYPASS=1" >&2
  hook_backup="$(dirname "$0")/pre-push.sentinel-backup"
  if [ -x "$hook_backup" ]; then
    exec "$hook_backup" "$@"
  fi
  exit 0
fi

python -m sentinel scan --repo "$(git rev-parse --show-toplevel)" --trigger pre-push
rc=$?
if [ $rc -ne 0 ]; then
  echo "[Sentinel] push aborted (exit $rc)" >&2
  exit $rc
fi

hook_backup="$(dirname "$0")/pre-push.sentinel-backup"
if [ -x "$hook_backup" ]; then
  exec "$hook_backup" "$@"
fi
exit 0
"""
```

- [ ] **Step 4: Write** `sentinel/hook/installer.py`:

```python
"""Git pre-push hook installer.

Contracts (see M1 design spec):
- Idempotent: running install twice = running once.
- Chaining: if a pre-push hook exists, Sentinel saves it as
  `pre-push.sentinel-backup` and invokes it on exit 0.
- Never clobbers the user's original hook: uninstall restores from backup.
"""
from __future__ import annotations
import os
import stat
from pathlib import Path

from sentinel.hook.payload import HOOK_SCRIPT, SENTINEL_MARKER


class HookInstallError(Exception):
    """Raised when install/uninstall cannot proceed safely."""


def is_sentinel_hook(hook_path: Path) -> bool:
    if not hook_path.is_file():
        return False
    try:
        content = hook_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return SENTINEL_MARKER in content


def install_hook(repo_root: Path) -> None:
    git_dir = repo_root / ".git"
    if not git_dir.is_dir():
        raise HookInstallError(f"not a git repository: {repo_root}")
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook = hooks_dir / "pre-push"
    backup = hooks_dir / "pre-push.sentinel-backup"

    if hook.exists() and not is_sentinel_hook(hook):
        if not backup.exists():
            backup.write_bytes(hook.read_bytes())
            _chmod_exec(backup)

    hook.write_text(HOOK_SCRIPT, encoding="utf-8")
    _chmod_exec(hook)


def uninstall_hook(repo_root: Path) -> None:
    hooks_dir = repo_root / ".git" / "hooks"
    hook = hooks_dir / "pre-push"
    backup = hooks_dir / "pre-push.sentinel-backup"
    if backup.exists():
        hook.write_bytes(backup.read_bytes())
        _chmod_exec(hook)
        backup.unlink()
    elif hook.exists() and is_sentinel_hook(hook):
        hook.unlink()


def _chmod_exec(path: Path) -> None:
    try:
        current = path.stat().st_mode
        path.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass
```

- [ ] **Step 5: Write** `sentinel/hook/__init__.py`:

```python
from sentinel.hook.installer import (
    HookInstallError,
    install_hook,
    is_sentinel_hook,
    uninstall_hook,
)

__all__ = ["HookInstallError", "install_hook", "is_sentinel_hook", "uninstall_hook"]
```

- [ ] **Step 6:** `python -m pytest tests/unit/test_hook_installer.py -v` → 7 passed.

- [ ] **Step 7: Commit:**

```bash
cd C:/Sentinel
git checkout -b m2/hook-and-rules
git add sentinel/hook/__init__.py sentinel/hook/installer.py sentinel/hook/payload.py tests/unit/test_hook_installer.py
git commit -m "feat(hook): pre-push hook installer with idempotent chaining"
```

---

## Task 2: CLI install-hook / uninstall-hook subcommands

**Files:**
- Create: `C:\Sentinel\sentinel\cli\install_hook.py`
- Modify: `C:\Sentinel\sentinel\cli\__main__.py`
- Create: `C:\Sentinel\tests\unit\test_cli_install_hook.py`

- [ ] **Step 1: Write failing test** `tests/unit/test_cli_install_hook.py`:

```python
import subprocess
import sys
from pathlib import Path

SENTINEL_ROOT = Path(__file__).parent.parent.parent


def _make_git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git" / "hooks").mkdir(parents=True)
    return repo


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(SENTINEL_ROOT),
    )


def test_install_hook_cli_writes_hook(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    res = _run("install-hook", "--repo", str(repo))
    assert res.returncode == 0, f"stderr: {res.stderr}"
    assert (repo / ".git" / "hooks" / "pre-push").exists()


def test_install_hook_cli_non_git_errors(tmp_path: Path):
    res = _run("install-hook", "--repo", str(tmp_path))
    assert res.returncode == 1
    assert "not a git repository" in res.stderr.lower()


def test_uninstall_hook_cli_removes_hook(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    _run("install-hook", "--repo", str(repo))
    res = _run("uninstall-hook", "--repo", str(repo))
    assert res.returncode == 0
    assert not (repo / ".git" / "hooks" / "pre-push").exists()
```

- [ ] **Step 2:** `python -m pytest tests/unit/test_cli_install_hook.py -v` → FAIL.

- [ ] **Step 3: Write** `sentinel/cli/install_hook.py`:

```python
"""`sentinel install-hook` / `sentinel uninstall-hook` subcommands."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

from sentinel.hook import HookInstallError, install_hook, uninstall_hook


def add_install_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("install-hook", help="Install the Sentinel pre-push hook")
    p.add_argument("--repo", type=Path, required=True, help="Target repo root")
    p.set_defaults(func=_run_install)


def add_uninstall_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("uninstall-hook", help="Uninstall the Sentinel pre-push hook")
    p.add_argument("--repo", type=Path, required=True, help="Target repo root")
    p.set_defaults(func=_run_uninstall)


def _run_install(args: argparse.Namespace) -> int:
    try:
        install_hook(args.repo)
    except HookInstallError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"[Sentinel] hook installed at {args.repo}/.git/hooks/pre-push")
    return 0


def _run_uninstall(args: argparse.Namespace) -> int:
    uninstall_hook(args.repo)
    print(f"[Sentinel] hook uninstalled from {args.repo}")
    return 0
```

- [ ] **Step 4: Modify** `sentinel/cli/__main__.py` to register the two subcommands. Add:

```python
from sentinel.cli import install_hook as install_hook_cmd
# ... inside main(), after explain_cmd.add_subparser(sub):
install_hook_cmd.add_install_subparser(sub)
install_hook_cmd.add_uninstall_subparser(sub)
```

- [ ] **Step 5:** `python -m pytest tests/unit/test_cli_install_hook.py -v` → 3 passed.

- [ ] **Step 6: Commit:**

```bash
git add sentinel/cli/install_hook.py sentinel/cli/__main__.py tests/unit/test_cli_install_hook.py
git commit -m "feat(cli): install-hook / uninstall-hook subcommands"
```

---

## Task 3: Rule 4 — P0-claude-config-committed (YAML)

**Files:**
- Create: `sentinel/rules/yaml/P0-claude-config-committed.yaml`
- Create: `tests/fixtures/repos/claude_config_BAD/.claude/settings.json`
- Create: `tests/fixtures/repos/claude_config_GOOD/.gitignore`
- Create: `tests/unit/test_rule_claude_config.py`

The rule pattern is a filename/path pattern, not a content pattern. Sentinel's YAML rules
currently scan file CONTENTS. For this rule we need to detect the mere EXISTENCE of files
under `.claude/`, `.gemini/`, `.codex/`. Approach: the YAML rule's `pattern` is a regex
that matches any non-empty content (`.+` or `.*`), combined with `files:` globs that only
match those paths. This produces a BLOCK verdict pointing at each file inside those dirs.

- [ ] **Step 1: Write** `sentinel/rules/yaml/P0-claude-config-committed.yaml`:

```yaml
id: P0-claude-config-committed
severity: BLOCK
scope: repo
description: >
  Agent tool configuration directories (.claude/, .gemini/, .codex/) must
  never be committed to public repos per CLAUDE.md#config-safety.
pattern: '.'
files:
  - '.claude/**'
  - '.gemini/**'
  - '.codex/**'
exclude: []
fix_hint: >
  Add .claude/, .gemini/, .codex/ to .gitignore and remove tracked files
  with `git rm -r --cached .claude/ .gemini/ .codex/`.
source: CLAUDE.md#config-safety
```

- [ ] **Step 2: Write** fixture `tests/fixtures/repos/claude_config_BAD/.claude/settings.json`:

```json
{"theme": "dark"}
```

- [ ] **Step 3: Write** fixture `tests/fixtures/repos/claude_config_GOOD/.gitignore`:

```
.claude/
.gemini/
.codex/
```

- [ ] **Step 4: Write** `tests/unit/test_rule_claude_config.py`:

```python
from pathlib import Path
from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.yaml_loader import load_yaml_rule


RULE_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "yaml" / "P0-claude-config-committed.yaml"
)


def test_claude_config_fires_on_bad_fixture(fixtures_dir: Path):
    rule = load_yaml_rule(RULE_PATH)
    bad = fixtures_dir / "repos" / "claude_config_BAD"
    verdicts = rule.check(RepoContext(repo_root=bad, mode=ScanMode.REPO))
    assert len(verdicts) >= 1
    assert all(v.severity == Severity.BLOCK for v in verdicts)


def test_claude_config_silent_on_good_fixture(fixtures_dir: Path):
    rule = load_yaml_rule(RULE_PATH)
    good = fixtures_dir / "repos" / "claude_config_GOOD"
    verdicts = rule.check(RepoContext(repo_root=good, mode=ScanMode.REPO))
    assert verdicts == []
```

- [ ] **Step 5:** `python -m pytest tests/unit/test_rule_claude_config.py -v` → 2 passed.

- [ ] **Step 6: Commit:**

```bash
git add sentinel/rules/yaml/P0-claude-config-committed.yaml tests/fixtures/repos/claude_config_BAD/.claude/settings.json tests/fixtures/repos/claude_config_GOOD/.gitignore tests/unit/test_rule_claude_config.py
git commit -m "feat(rules): P0-claude-config-committed YAML rule"
```

---

## Task 4: Rule 5 — P0-hardcoded-local-path (YAML)

**Files:**
- Create: `sentinel/rules/yaml/P0-hardcoded-local-path.yaml`
- Create: `tests/fixtures/repos/hardcoded_path_BAD/dashboard.html`
- Create: `tests/fixtures/repos/hardcoded_path_GOOD/dashboard.html`
- Create: `tests/unit/test_rule_hardcoded_local_path.py`

- [ ] **Step 1: Write** `sentinel/rules/yaml/P0-hardcoded-local-path.yaml`:

```yaml
id: P0-hardcoded-local-path
severity: BLOCK
scope: repo
description: >
  Shipped code must not contain absolute local paths like `C:\Users\...` or
  `/home/<user>/...` per lessons.md#code-quality. These leak developer
  environment details and break portability.
pattern: '(C:[\\/]Users[\\/][^\s\"\\/]+|/home/[a-z_][a-z0-9_-]*)'
files:
  - '**/*.html'
  - '**/*.js'
  - '**/*.css'
  - '**/*.md'
  - '**/*.py'
  - '**/*.json'
  - '**/*.yaml'
  - '**/*.yml'
exclude:
  - 'tests/**'
  - 'fixtures/**'
  - 'docs/superpowers/**'
  - 'PROGRESS.md'
  - '.git/**'
fix_hint: >
  Replace absolute paths with relative paths, config-driven roots, or
  environment variables. Use candidate-root discovery for data snapshots.
source: lessons.md#code-quality
```

- [ ] **Step 2: Write** fixture `tests/fixtures/repos/hardcoded_path_BAD/dashboard.html`:

```html
<html><body>
<script>const DATA = "C:/Users/mahmood/data.json";</script>
</body></html>
```

- [ ] **Step 3: Write** fixture `tests/fixtures/repos/hardcoded_path_GOOD/dashboard.html`:

```html
<html><body>
<script>const DATA = "./data.json";</script>
</body></html>
```

- [ ] **Step 4: Write** test `tests/unit/test_rule_hardcoded_local_path.py` (same shape as Task 3 test, substituting rule path + fixture dirs + rule id `P0-hardcoded-local-path`).

- [ ] **Step 5:** `python -m pytest tests/unit/test_rule_hardcoded_local_path.py -v` → 2 passed.

- [ ] **Step 6: Commit** with message `feat(rules): P0-hardcoded-local-path YAML rule`.

---

## Task 5: Rule 6 — P1-unpopulated-placeholder (YAML)

**Pattern:** `\{\{[^}]+\}\}|REPLACE_ME|__PLACEHOLDER__|TBD:|XXX:`
(matches Jinja-style `{{foo}}`, literal REPLACE_ME, `__PLACEHOLDER__`, TBD: / XXX: tags).

**Severity:** WARN (per spec).

- [ ] **Step 1:** Write `sentinel/rules/yaml/P1-unpopulated-placeholder.yaml`:

```yaml
id: P1-unpopulated-placeholder
severity: WARN
scope: repo
description: >
  Unpopulated template placeholders (Jinja braces, REPLACE_ME, TBD markers)
  should not ship in built assets per html-apps.md#safety-checks.
pattern: '\{\{[^}]+\}\}|REPLACE_ME|__PLACEHOLDER__|TBD:|XXX:'
files:
  - '**/*.html'
  - '**/*.md'
  - '**/*.js'
  - '**/*.py'
exclude:
  - 'tests/**'
  - 'fixtures/**'
  - 'docs/superpowers/**'
  - 'templates/**'
  - '.git/**'
fix_hint: >
  Populate the placeholder or escape it before shipping. If the braces are
  intentional template syntax in a non-template file, exclude the file path
  via the rule's exclude list.
source: html-apps.md#safety-checks
```

- [ ] **Step 2:** Fixture BAD: `tests/fixtures/repos/placeholder_BAD/readme.md` contains `Welcome to {{PROJECT_NAME}}. See REPLACE_ME for details.`
- [ ] **Step 3:** Fixture GOOD: `tests/fixtures/repos/placeholder_GOOD/readme.md` contains `Welcome to Sentinel. See docs/ for details.`
- [ ] **Step 4:** Write test `tests/unit/test_rule_unpopulated_placeholder.py` (same shape).
- [ ] **Step 5:** `pytest` → 2 passed.
- [ ] **Step 6:** Commit `feat(rules): P1-unpopulated-placeholder YAML rule`.

---

## Task 6: Rule 7 — P1-silent-failure-sentinel (YAML)

**Pattern:** matches `return "unknown_` or `return 'unknown_` literals on a single line
(silent failure sentinel pattern from MetaReproducer P0-1 incident).

- [ ] **Step 1:** Write `sentinel/rules/yaml/P1-silent-failure-sentinel.yaml`:

```yaml
id: P1-silent-failure-sentinel
severity: WARN
scope: repo
description: >
  Silent failure sentinels like `return "unknown_..."` hide schema errors
  and let pipelines complete with corrupted output per
  lessons.md#integration-contracts. Prefer raising KeyError with the
  expected-vs-received key diff.
pattern: 'return\s+[\"''](unknown_|__silent__|__fail__)'
files:
  - '**/*.py'
exclude:
  - 'tests/**'
  - 'fixtures/**'
  - '.git/**'
fix_hint: >
  Raise KeyError or a domain-specific exception instead of returning a
  sentinel string. Include expected-vs-received schema in the exception
  message.
source: lessons.md#integration-contracts
```

- [ ] **Step 2:** Fixture BAD: `tests/fixtures/repos/silent_failure_BAD/module.py` with `def classify(d):\n    if "kind" not in d:\n        return "unknown_ratio"\n    return d["kind"]\n`.
- [ ] **Step 3:** Fixture GOOD: same `module.py` but raising `KeyError` instead.
- [ ] **Step 4:** Write test.
- [ ] **Step 5:** `pytest` → 2 passed.
- [ ] **Step 6:** Commit `feat(rules): P1-silent-failure-sentinel YAML rule`.

---

## Task 7: Rule 8 — P1-script-in-template-literal (YAML)

**Pattern:** the literal string `</script>` on a single line (context-insensitive; the
fixtures ensure BAD places it inside a template literal while GOOD escapes it).

This rule is intentionally coarse — it flags any `</script>` inside files that would
render embedded scripts. The WARN tier is appropriate because false positives are
possible but the risk of a real positive (breaking `<script>` blocks) is high.

- [ ] **Step 1:** Write `sentinel/rules/yaml/P1-script-in-template-literal.yaml`:

```yaml
id: P1-script-in-template-literal
severity: WARN
scope: repo
description: >
  Literal "</script>" appearing inside a .html / .js file usually indicates
  an unescaped closer inside a template literal or comment per
  lessons.md#javascript-html. Escape with `${'<'}/script>` to be safe.
pattern: '<\/script>'
files:
  - '**/*.html'
  - '**/*.js'
exclude:
  - 'tests/**'
  - 'fixtures/**'
  - '.git/**'
fix_hint: >
  Replace `</script>` inside template literals or comments with
  `${'<'}/script>` to prevent the HTML parser from terminating the
  surrounding script block.
source: lessons.md#javascript-html
```

Note: Fixture BAD must place `</script>` inside a template literal WITHIN a `<script>`
block. Fixture GOOD uses the `${'<'}/script>` escape. Rule pattern fires on the raw
occurrence in either case — so the GOOD fixture should not contain `</script>` at all;
use the escape instead.

- [ ] **Step 2:** Fixture BAD `tests/fixtures/repos/script_template_BAD/index.html`:
```html
<script>const x = `<html><script>alert(1)</script></html>`;</script>
```
(the inner `</script>` is what the rule catches)

- [ ] **Step 3:** Fixture GOOD `tests/fixtures/repos/script_template_GOOD/index.html`:
```html
<script>const x = `<html><script>alert(1)${'<'}/script></html>`;</script>
```

Wait — the GOOD fixture still contains the outer `</script>` which would match the
pattern. This is a false positive risk the rule accepts at WARN tier. For the test,
we want GOOD to return zero verdicts, so we cannot have ANY `</script>` at all.

Revised GOOD: use an HTML file with no `</script>` tags:
```html
<div>hello world</div>
```

This is still valid HTML without scripts. The GOOD fixture tests that a script-less
file produces no verdicts. The BAD fixture tests that the rule catches the literal
occurrence inside a template string.

(If this simplification makes the test less meaningful, consider making the rule's
pattern stricter in a follow-up — e.g., require that the match be inside backticks.
For M2 this WARN-tier coarse rule is sufficient.)

- [ ] **Step 4:** Write test.
- [ ] **Step 5:** `pytest` → 2 passed.
- [ ] **Step 6:** Commit `feat(rules): P1-script-in-template-literal YAML rule`.

---

## Task 8: Rule 9 — P0-workbook-rewrite-touched (Python plugin)

This rule cannot be a simple YAML pattern matcher. It needs to parse `git diff` output
for the staged changes and check whether the diff touches any line inside a
`YOUR REWRITE:` block in `rewrite-workbook.txt`.

**Files:**
- Create: `sentinel/rules/plugins/workbook_rewrite_touched.py`
- Create: `tests/fixtures/workbook_fixtures/` (sample diff patches + workbook)
- Create: `tests/unit/test_rule_workbook_rewrite_touched.py`

**Design:** The plugin does the following in `check(ctx)`:
1. Locate `rewrite-workbook.txt` in the repo root (if absent, skip: return []).
2. Run `git diff --cached --unified=0` in `ctx.repo_root`.
3. For each diff hunk touching `rewrite-workbook.txt`, extract the touched line ranges.
4. Parse `rewrite-workbook.txt` to find `YOUR REWRITE:` blocks and their line ranges.
5. If any touched range intersects a `YOUR REWRITE:` block range, emit a BLOCK verdict.

**For testing**, the plugin accepts an optional `_diff_override: Optional[str]` keyword
on a module-level `check` wrapper so tests don't need to construct a real git repo.
Production callers never pass this.

- [ ] **Step 1:** Write failing test `tests/unit/test_rule_workbook_rewrite_touched.py`:

```python
import textwrap
from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule


PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "workbook_rewrite_touched.py"
)

WORKBOOK = textwrap.dedent("""\
    ENTRY 1/3
    CURRENT BODY:
      Lorem ipsum dolor sit amet.
    YOUR REWRITE:
      This is the user's protected rewrite.
      Second line of the rewrite.
    SUBMITTED: [ ]
    ---
    ENTRY 2/3
    CURRENT BODY:
      Body 2.
    YOUR REWRITE:
      Rewrite 2 line 1.
    SUBMITTED: [x]
""")


DIFF_TOUCHES_YOUR_REWRITE = textwrap.dedent("""\
    diff --git a/rewrite-workbook.txt b/rewrite-workbook.txt
    index 0000000..1111111 100644
    --- a/rewrite-workbook.txt
    +++ b/rewrite-workbook.txt
    @@ -5,1 +5,1 @@ ENTRY 1/3
    -  This is the user's protected rewrite.
    +  TAMPERED LINE BY CLAUDE
    """)


DIFF_TOUCHES_CURRENT_BODY_ONLY = textwrap.dedent("""\
    diff --git a/rewrite-workbook.txt b/rewrite-workbook.txt
    index 0000000..1111111 100644
    --- a/rewrite-workbook.txt
    +++ b/rewrite-workbook.txt
    @@ -3,1 +3,1 @@ CURRENT BODY
    -  Lorem ipsum dolor sit amet.
    +  Improved body text.
    """)


def _setup(tmp_path: Path) -> Path:
    (tmp_path / "rewrite-workbook.txt").write_text(WORKBOOK, encoding="utf-8")
    return tmp_path


def test_workbook_rule_blocks_when_rewrite_touched(tmp_path: Path, monkeypatch):
    repo = _setup(tmp_path)
    rule = load_plugin_rule(PLUGIN_PATH)

    # The plugin reads from an env var SENTINEL_TEST_DIFF to inject diff text.
    monkeypatch.setenv("SENTINEL_TEST_DIFF", DIFF_TOUCHES_YOUR_REWRITE)

    verdicts = rule.check(RepoContext(repo_root=repo, mode=ScanMode.REPO))
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "P0-workbook-rewrite-touched"
    assert verdicts[0].severity == Severity.BLOCK


def test_workbook_rule_silent_when_only_current_body_touched(tmp_path, monkeypatch):
    repo = _setup(tmp_path)
    rule = load_plugin_rule(PLUGIN_PATH)
    monkeypatch.setenv("SENTINEL_TEST_DIFF", DIFF_TOUCHES_CURRENT_BODY_ONLY)
    assert rule.check(RepoContext(repo_root=repo, mode=ScanMode.REPO)) == []


def test_workbook_rule_silent_when_no_workbook_in_repo(tmp_path, monkeypatch):
    # Empty repo, no rewrite-workbook.txt
    rule = load_plugin_rule(PLUGIN_PATH)
    monkeypatch.setenv("SENTINEL_TEST_DIFF", DIFF_TOUCHES_YOUR_REWRITE)
    assert rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)) == []
```

- [ ] **Step 2:** `pytest` → FAIL.

- [ ] **Step 3:** Write `sentinel/rules/plugins/workbook_rewrite_touched.py`:

```python
"""P0-workbook-rewrite-touched: BLOCK if a staged diff touches a
YOUR REWRITE: section in rewrite-workbook.txt.

Testing aid: honors env var SENTINEL_TEST_DIFF to bypass git invocation."""
from __future__ import annotations
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Set

from sentinel.core import RepoContext, Severity, Verdict


ID = "P0-workbook-rewrite-touched"
SEVERITY = Severity.BLOCK
SOURCE = "CLAUDE.md#workbook-protection"
SCOPE = "repo"

WORKBOOK_BASENAME = "rewrite-workbook.txt"
REWRITE_HEADER = "YOUR REWRITE:"
BLOCK_TERMINATORS = ("SUBMITTED:", "CURRENT BODY:", "ENTRY ", "---")


def _protected_line_ranges(workbook_text: str) -> List[tuple]:
    """Return list of (start_line, end_line) 1-indexed ranges, inclusive."""
    lines = workbook_text.splitlines()
    ranges: List[tuple] = []
    in_rewrite = False
    start = None
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith(REWRITE_HEADER):
            in_rewrite = True
            start = idx + 1
            continue
        if in_rewrite and any(stripped.startswith(t) for t in BLOCK_TERMINATORS):
            if start is not None:
                ranges.append((start, idx - 1))
            in_rewrite = False
            start = None
    if in_rewrite and start is not None:
        ranges.append((start, len(lines)))
    return ranges


_HUNK_RE = re.compile(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@')


def _touched_lines_in_workbook(diff_text: str) -> Set[int]:
    touched: Set[int] = set()
    in_workbook = False
    current_line = 0
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            in_workbook = WORKBOOK_BASENAME in line
            continue
        if not in_workbook:
            continue
        m = _HUNK_RE.match(line)
        if m:
            current_line = int(m.group(1))
            continue
        if line.startswith("+") and not line.startswith("+++"):
            touched.add(current_line)
            current_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            pass  # deletions don't advance the new-file counter
        elif line.startswith(" "):
            current_line += 1
    return touched


def _get_diff(repo_root: Path) -> str:
    override = os.environ.get("SENTINEL_TEST_DIFF")
    if override is not None:
        return override
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--unified=0"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""
    return result.stdout


def check(ctx: RepoContext) -> List[Verdict]:
    workbook = ctx.repo_root / WORKBOOK_BASENAME
    if not workbook.is_file():
        return []
    workbook_text = workbook.read_text(encoding="utf-8", errors="replace")
    protected = _protected_line_ranges(workbook_text)
    if not protected:
        return []

    diff_text = _get_diff(ctx.repo_root)
    touched = _touched_lines_in_workbook(diff_text)
    if not touched:
        return []

    hits = [
        line for line in touched
        if any(start <= line <= end for start, end in protected)
    ]
    if not hits:
        return []

    return [
        Verdict(
            rule_id=ID,
            severity=SEVERITY,
            repo=str(ctx.repo_root),
            file=WORKBOOK_BASENAME,
            line=min(hits),
            detail=(
                f"staged diff touches protected YOUR REWRITE: section "
                f"at lines {sorted(hits)}"
            ),
            fix_hint=(
                "The YOUR REWRITE: block is sacrosanct per CLAUDE.md. "
                "Revert those lines and commit only CURRENT BODY changes. "
                "If the user authorized the rewrite edit, bypass Sentinel "
                "for this push with SENTINEL_BYPASS=1."
            ),
            source=SOURCE,
            timestamp=datetime.now(timezone.utc),
        )
    ]
```

- [ ] **Step 4:** `pytest tests/unit/test_rule_workbook_rewrite_touched.py -v` → 3 passed.

- [ ] **Step 5: Commit** `feat(rules): P0-workbook-rewrite-touched git-diff plugin`.

---

## Task 9: Hook-chaining non-regression test

**Files:**
- Create: `tests/regression/test_hook_chaining_idempotent.py`

This is the fourth non-regression guarantee from the M1 spec (deferred to M2 because the installer didn't exist then).

- [ ] **Step 1: Write** `tests/regression/test_hook_chaining_idempotent.py`:

```python
"""Non-regression: installing the hook twice leaves one Sentinel hook in
place and preserves any pre-existing hook via the backup."""
from pathlib import Path
import pytest

from sentinel.hook import install_hook, is_sentinel_hook


def _git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git" / "hooks").mkdir(parents=True)
    return repo


@pytest.mark.regression
def test_double_install_matches_single(tmp_path: Path):
    a = _git_repo(tmp_path / "a")
    b = _git_repo(tmp_path / "b")

    install_hook(a)
    install_hook(b)
    install_hook(b)  # second install on b

    hook_a = (a / ".git" / "hooks" / "pre-push").read_text(encoding="utf-8")
    hook_b = (b / ".git" / "hooks" / "pre-push").read_text(encoding="utf-8")
    assert hook_a == hook_b
    assert is_sentinel_hook(a / ".git" / "hooks" / "pre-push")
    assert is_sentinel_hook(b / ".git" / "hooks" / "pre-push")


@pytest.mark.regression
def test_double_install_with_existing_hook_preserves_one_backup(tmp_path: Path):
    repo = _git_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-push"
    hook.write_text("#!/bin/sh\necho original\n", encoding="utf-8")

    install_hook(repo)
    install_hook(repo)

    backup = repo / ".git" / "hooks" / "pre-push.sentinel-backup"
    assert backup.read_text(encoding="utf-8") == "#!/bin/sh\necho original\n"
    assert not (repo / ".git" / "hooks" / "pre-push.sentinel-backup.sentinel-backup").exists()


@pytest.mark.regression
def test_install_preserves_prior_hook_functionality(tmp_path: Path):
    """After install, the Sentinel hook references the backup so the prior
    hook is reachable (not overwritten)."""
    repo = _git_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-push"
    hook.write_text("#!/bin/sh\necho original\n", encoding="utf-8")
    install_hook(repo)
    new = hook.read_text(encoding="utf-8")
    assert "pre-push.sentinel-backup" in new
```

- [ ] **Step 2:** `pytest tests/regression/test_hook_chaining_idempotent.py -v` → 3 passed.

- [ ] **Step 3: Commit** `test(regression): hook-chaining idempotency guarantee`.

---

## Task 10: M2 pre-deploy validation

**Files:** none created; this task is a smoke-test batch.

- [ ] **Step 1:** Run full suite with coverage:
```bash
cd C:/Sentinel
python -m pytest --cov --cov-report=term-missing
```
Expected: all tests pass (M1 55 + M2 ~20 = ~75). Coverage on core+registry still ≥90%.

- [ ] **Step 2:** Verify `sentinel list-rules` lists all 9 rules (the 3 from M1 + 6 new).

- [ ] **Step 3:** End-to-end on Sentinel's own repo:
```bash
cd C:/Sentinel
python -m sentinel install-hook --repo .
# Make a trivial commit; git push --dry-run origin m2/hook-and-rules
```
Expected: hook runs, scan returns 0 (Sentinel's own repo should be clean), push proceeds.

- [ ] **Step 4:** End-to-end with BAD repo:
```bash
mkdir -p C:/tmp/sentinel_m2_e2e/bad
cd C:/tmp/sentinel_m2_e2e/bad
git init
echo '{"sig":"SIG_RSA_SHA256_x"}' > cert.json
git add cert.json
git commit -m "test"
python -m sentinel install-hook --repo .
# Try to push to a fake remote; expect hook to block.
git push file:///tmp/nowhere HEAD  # will fail at remote, but hook must run first
```
Expected: Sentinel output contains `P0-placeholder-hmac` BLOCK; push is aborted before the network attempt.

- [ ] **Step 5: Commit** a PROGRESS.md update + intermediate checkpoint.

---

## Task 11: Deploy to shifaa (first target repo)

**NOTE:** These deployment tasks modify `.git/hooks/pre-push` in the target repo.
Hooks are NOT tracked by git, so no commits land in the target repo. However the
working directory is changed. Per CLAUDE.md's environment rules, confirm with
user before each deployment if running in interactive mode.

- [ ] **Step 1:** Install hook: `python -m sentinel install-hook --repo C:/Projects/shifaa`
- [ ] **Step 2:** Dry-run scan: `python -m sentinel scan --repo C:/Projects/shifaa`
      Capture the summary in PROGRESS.md.
- [ ] **Step 3:** If any BLOCK verdicts fired: document each one in PROGRESS.md under
      `M2 Target: shifaa` — that's the "one real BLOCK event caught in the wild" exit criterion.
- [ ] **Step 4:** If no BLOCK: move on. A clean scan is still a deployment success.

## Tasks 12–15: Deploy to MetaAudit, MES, overmind, cardiosynth

Each task repeats Task 11's three steps against the next target repo. Mark each in
PROGRESS.md with: install-hook timestamp, scan summary, any BLOCK events, fix notes.

## Task 16: M2 final validation + tag `m2-hook-rules`

- [ ] **Step 1:** Run the full suite one last time on Sentinel's repo.
- [ ] **Step 2:** Verify all 5 target repos have the hook installed:
```bash
for r in shifaa MetaAudit Models/MES overmind cardiosynth; do
  test -f "C:/$r/.git/hooks/pre-push" && echo "$r: OK"
done
```
- [ ] **Step 3:** Count real-world BLOCK events caught: aim for ≥1 per the exit criterion.
- [ ] **Step 4:** Tag the release:
```bash
cd C:/Sentinel
git tag -a m2-hook-rules -m "M2: pre-push hook + rules 4-9 + deployed to 5 repos"
```
- [ ] **Step 5:** Update PROGRESS.md with the M3 handoff.

---

## Self-Review

**Spec coverage (M2 section of design):**
- Pre-push hook installer (idempotent, chaining): Task 1 + Task 2 + Task 9 regression.
- Rules 4–9: Tasks 3–8.
- Install hook on 5 target repos: Tasks 11–15.
- One real BLOCK event caught: Task 11 step 3 explicitly tracks this.
- Non-regression hook-chaining test: Task 9.

**Placeholder scan:** No "TBD" / "fill in details" / "add appropriate error handling" in the plan. Every YAML rule body is complete. Every test body is complete. Shorthand "same shape as Task 3 test" for Tasks 4–7 is explicitly qualified with what to substitute (rule path + fixture dirs + rule id) — an engineer can expand it mechanically.

**Type consistency:** `HookInstallError`, `install_hook`, `uninstall_hook`, `is_sentinel_hook` used consistently. `SENTINEL_TEST_DIFF` env-var convention stated once in the plugin and used in tests. `SENTINEL_BYPASS=1` referenced consistently in payload + bypass logic.

**Known deliberate choices:**
- Task 7's `P1-script-in-template-literal` rule is coarse; accepted at WARN tier.
- Rule 4 (`P0-claude-config-committed`) uses a content-pattern hack (`.` matches any content) to get file-existence detection; noted inline.
- Task 8's workbook plugin uses `SENTINEL_TEST_DIFF` env var as testing aid; acknowledged and documented in the plugin.
