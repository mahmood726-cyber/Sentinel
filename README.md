# Sentinel

<!-- sentinel:skip-file — README documents the patterns Sentinel flags; it should not fire on itself (see docs/THREAT_MODEL.md §3.1) -->

> **Your AI coding agent will make these mistakes. Sentinel catches them at `git push`.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/downloads/)
[![tests](https://img.shields.io/badge/tests-regression--backed-brightgreen.svg)](#testing)
[![rules](https://img.shields.io/badge/rules-53%20built--in-blue.svg)](#built-in-rules)
[![pre--push](https://img.shields.io/badge/pre--push-~2s-brightgreen.svg)](#how-fast)

A **pre-push rule engine** for the Claude-Code / Cursor / Copilot / Codex era. Turns "don't commit `C:\Users\...` paths" and "don't ship placeholder HMAC signatures" and "don't claim an agent-config version your `pyproject.toml` disagrees with" into **executable checks that run before every `git push`** — in under 2 seconds, with zero CI.

When Sentinel fires, you see exactly which line of which file broke which rule. When it doesn't fire, your push goes through untouched.

```console
$ git push
[Sentinel] scanning 234 tracked files across the active ruleset...
  [BLOCK] P0-hardcoded-local-path   src/loader.py:12
          DATA = r"C:\Users\alice\Projects\scratch\data.csv"
  [BLOCK] P0-placeholder-hmac       bundle.json:9
          "signature_placeholder": "SIG_RSA_SHA256_mock"
[Sentinel] 2 BLOCK, 0 WARN. Push aborted.
Fix the findings above, or override with `SENTINEL_BYPASS=1 git push` (logged).
```

## Why this exists

LLM coding agents consistently write these classes of bug:
- Hardcoded absolute paths (`C:\Users\you\...`, `/home/you/...`) that work locally and break for everyone else
- Placeholder HMAC signatures that ship as "real" crypto
- Silent-failure sentinels (`return "unknown_ratio"`) that hide schema errors and corrupt downstream data
- Committed `.claude/`, `.gemini/`, `.codex/` agent configs (leaks + bloat)
- Stale version claims in `AGENTS.md`/`CLAUDE.md` while `pyproject.toml` moved on
- Unpopulated Jinja placeholders (`{{user_name}}`, `REPLACE_ME`, `TBD:`) shipping to production
- Registry drift (four registries with four different answers to "how many projects are there?")

**A single `CLAUDE.md` can ask the agent to avoid these. Sentinel makes it impossible to push them.** Advisory vs enforcement is the entire ROI case.

## What makes this different

| | Sentinel | Semgrep | pre-commit.com | CLAUDE.md alone |
|---|---|---|---|---|
| Runs pre-push on `git push` | ✅ ~2s | CI (slower) | ✅ but pre-commit | advisory |
| Rules tuned to AI-agent failure modes | ✅ | general-purpose | framework only | — |
| Each rule has a real-incident regression fixture | ✅ 17 fixtures | curated community rules | — | — |
| Cross-repo data-plane contract (nightly aggregator) | ✅ with [Overmind](#overmind-integration) | — | — | — |
| Drift verification for `MEMORY.md` / indices | ✅ via scripts | — | — | — |
| Rule-doc dogfooding (self-skip via marker) | ✅ `sentinel:skip-file` | — | — | — |
| Formal threat model | ✅ [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | ✅ (enterprise) | — | — |

Sentinel is **not** a replacement for Semgrep (which is mature, general, and ecosystem-backed). Sentinel is what you add when your failure modes are specific — agent-config version drift, workbook protection, registry reconciliation — and standard rulesets don't cover them.

## Quick start

```bash
# Clone + install
git clone https://github.com/mahmood726-cyber/Sentinel.git
cd Sentinel
pip install -e ".[dev]"

# See what rules exist
python -m sentinel list-rules

# Scan a repo without installing the hook (try first)
python -m sentinel scan --repo /path/to/your/repo

# Install the pre-push hook in a repo
python -m sentinel install-hook --repo /path/to/your/repo

# Now every `git push` from that repo runs Sentinel first.
# Emergency override (logged to ~/.sentinel-logs/bypass.log):
SENTINEL_BYPASS=1 git push
```

Output goes to two files in the scanned repo:
- `STUCK_FAILURES.md` + `.jsonl` — BLOCK verdicts (abort push)
- `sentinel-findings.md` + `.jsonl` — WARN verdicts (logged, push proceeds)

Both are auto-added to the target repo's `.gitignore` on install.

## Built-in rules

Sentinel currently ships **53 built-in rules** (6 YAML + 47 Python plugins). Run `python -m sentinel list-rules` for the live count on your checkout.

### Generic code-quality

| Rule ID | Tier | What it catches |
|---|---|---|
| `P0-hardcoded-local-path` | BLOCK | `C:\Users\...`, `/home/...`, `D:\projects\...`, `/Users/...` in shipped code |
| `P0-placeholder-hmac` | BLOCK | `SIG_RSA_SHA256_`, `signature_placeholder` — faux crypto sigs |
| `P0-hmac-compare-eq` | BLOCK | `==` / `!=` on HMAC / signature / digest identifiers (timing-leak) |
| `P0-claude-config-committed` | BLOCK | `.claude/`, `.gemini/`, `.codex/` committed to a repo |
| `P0-workbook-rewrite-touched` | BLOCK | Edits to protected `YOUR REWRITE` sections |
| `P1-silent-failure-sentinel` | WARN | `return "unknown_ratio"` / `return "__silent__"` (silent failures) |
| `P1-unpopulated-placeholder` | WARN | `{{x}}`, `{{ x\|filter }}`, `REPLACE_ME`, `TBD:`, `XXX:` |
| `P1-empty-dataframe-access` | WARN | Unchecked `.iloc[0]` / `.values[0]` on possibly empty DataFrames |
| `P1-leaked-secret` | BLOCK | OpenAI / GitHub / AWS / Anthropic key shapes in tracked files |
| `P1-license-noncompliance` | WARN | Bundled dependencies whose declared license disagrees with the repo's LICENSE |
| `P1-cp1252-mojibake` | WARN | Canonical `â"€`, `â€"`, `â˜…` byte sequences (UTF-8 reopened in cp1252 editor) |
| `P1-blueprint-implementation-match` | WARN | `blueprint.json`-declared DOM ids that don't exist in any shipped `.html` file |
| `P2-agent-config-version-drift` | WARN | Stale version claims in `AGENTS.md` vs `pyproject.toml` |
| `P2-autogen-tracked` | WARN | Tracked auto-generated files (`PROGRESS.md`, `DECISIONS.md`, `stability_state.json`, etc.) |
| `P2-progress-md-not-gitignored` | INFO | Tracked `PROGRESS.md` (session state leaking) |
| `P2-html-a11y-basics` | INFO | `<html>` w/o `lang=`, missing `<title>`, `<img>` w/o `alt=`, unlabeled inputs |

### Python collection / runtime

| Rule ID | Tier | What it catches |
|---|---|---|
| `P1-py-parse-check` | BLOCK | Python files that fail to parse |
| `P1-py-package-init-tracked` | WARN | Importable package directory committed without `__init__.py` |
| `P1-test-module-collision` | BLOCK | Two `test_*.py` files sharing basename across dirs without `__init__.py` (pytest drops one) |
| `P1-module-stdout-reassign` | WARN | Module-level `sys.stdout = io.TextIOWrapper(...)` without a `"pytest" not in sys.modules` guard |
| `P1-regex-catastrophic-backtrack` | WARN | Nested unbounded quantifiers `(\w+)+`, `(.+)*` (ReDoS) |

### JavaScript / HTML

| Rule ID | Tier | What it catches |
|---|---|---|
| `P1-js-parse-check` | BLOCK | JS files that fail to parse |
| `P1-js-lockfile-present` | WARN | `package.json` without a `package-lock.json` in submission-ready JS repos |
| `P1-js-scripts-resolvable` | WARN | `package.json` scripts referencing files that don't exist |
| `P1-script-close-in-template` | BLOCK | Literal `</script>` inside a backtick template literal |
| `P1-nullish-or-mixed` | BLOCK | `?? \|\| ` or `?? &&` without explicit grouping parens (JS SyntaxError) |
| `P2-numeric-parse-or-null` | WARN | `parseFloat(x) \|\| null` silently dropping 0.0 |
| `P1-dashboard-match` | WARN | Rendered review's pooled HR/OR claim incompatible with its own realData block |

### E156 Assurance Standard

| Rule ID | Tier | What it catches |
|---|---|---|
| `P0-baseline-drift` | BLOCK | MissionCritical baseline corpus integrity |
| `P0-citation-cascade` | BLOCK | Citation chain integrity in the workbook |
| `P0-claim-language-workbook` | WARN (BLOCK with `SENTINEL_CLAIM_LANGUAGE_BLOCK=1`) | Causal-claim language without override marker |
| `P0-denominator-logic` | BLOCK | Inconsistent denominators across data extraction |
| `P0-e156-placeholder-leak` | BLOCK | Python `None` reaching JS object literals → `Uncaught ReferenceError` |
| `P0-rapidmeta-data-integrity` | BLOCK | Trial-data tampering in rapidmeta review files |
| `P1-cochrane-v65-invariants` | WARN | Cochrane v6.5 / RevMan 2025 numeric-reproducibility invariants |
| `P1-fabrication-implausible-precision` | WARN | BadScientist arXiv 2510.18003 — implausibly precise numbers |
| `P1-fabrication-orphan-trial` | WARN | BadScientist — trial cited but never linked to source |
| `P1-fabrication-round-number-cluster` | WARN | BadScientist — too many round numbers in one report |
| `P1-fabrication-self-contradiction` | WARN | BadScientist — body claim contradicts its own data table |
| `P1-fabrication-temporal-impossibility` | WARN | BadScientist — dates that can't have happened |
| `P2-hallucination-classifier` | WARN | HF Inference API hallucination score above threshold (scaffolded — needs HF_API_KEY) |
| `P2-dashboard-stat-orphan` | INFO | Dashboard stats with no matching upstream source |

### Portfolio scope

| Rule ID | Tier | What it catches |
|---|---|---|
| `P0-path-not-exist` | BLOCK (portfolio) | Registry paths that don't resolve on disk |
| `P0-registry-drift` | BLOCK (portfolio) | Multiple registries disagreeing on project count |
| `P0-livingmeta-drift` | BLOCK (portfolio) | Trial-ID drift between workbook and deployed HTML |
| `P2-memory-paths-resolve` | WARN (portfolio) | Paths cited in Claude memory files that don't resolve on disk |

## Writing your own rule

A YAML rule is ~20 lines. Drop it in `sentinel/rules/yaml/`:

```yaml
id: P1-my-custom-rule
severity: WARN
scope: repo
description: >
  Short description of what this catches and why.
pattern: 'YOUR_REGEX_HERE'
files:
  - '**/*.py'
  - '**/*.md'
exclude:
  - 'tests/**'
fix_hint: >
  One sentence explaining how to fix violations.
source: docs/lessons.md#your-lesson-anchor
```

That's it. `list-rules` will show it, `scan` will apply it, and the pre-push hook will enforce it.

More complex rules (portfolio-scope, cross-file, multi-step) can be Python plugins in `sentinel/rules/plugins/`. See `sentinel/rules/plugins/path_not_exist.py` for a minimal example.

## How fast

On a typical 500-file repo:
- `python -m sentinel scan` — **~0.8s**
- Pre-push hook (scan + decide) — **~1.5-2.5s**
- Full test suite — **~15s** on the author machine
- Nightly portfolio aggregation (via Overmind) — async, doesn't block pushes

Sentinel skips gitignored files (uses `git ls-files --cached --others --exclude-standard`), so scan time scales with tracked-file count, not total disk.

## Overmind integration

If you run [Overmind](https://github.com/mahmood726-cyber/overmind) as a nightly portfolio verifier, Sentinel's per-repo JSONL outputs aggregate into a portfolio-wide view. Key filenames and schema are locked via an end-to-end contract test so rename-regression (the class of bug that broke this link in an earlier version) can't silently recur.

## Skip-file marker

Rule-documentation files legitimately cite the patterns they describe and would fire dogfooding BLOCKs. Add a one-line marker to opt out of all rules on a specific file:

```markdown
<!-- sentinel:skip-file — this doc documents the patterns; scanning creates false-positive BLOCKs -->
```

```python
# sentinel:skip-file — test fixture with intentionally-bad patterns
```

The marker must appear in the **first 1KB** of the file — deeper markers don't count (see `docs/THREAT_MODEL.md §3.1`).

## Testing

```bash
python -m pytest                    # full suite
python -m pytest tests/regression   # 17-incident regression corpus
python -m pytest tests/unit         # per-rule unit tests
python -m pytest tests/integration  # cross-module integration
```

The `tests/regression/test_historical_incidents.py` corpus encodes **17 real past incidents** — each test uses the actual content (or minimally stripped equivalent) that caused a shipped bug, traced to a dated entry in `lessons.md` or a commit. If a rule is weakened in a way that lets one of these through, a regression test fires immediately.

## Threat model

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the documented security posture.

Short version: Sentinel is a **quality gate**, not a security boundary. It defends against user mistakes and AI-agent mistakes. It does NOT defend against an attacker with code-exec on your machine — at that point, the attacker has fully won.

## Contributing

Issues, PRs, and rule-proposal discussions are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the (short) ground rules.

If you have a class of AI-agent-generated bug that your CI keeps catching, Sentinel might be able to catch it pre-push instead. Open an issue with a minimal reproduction and we can discuss encoding it as a rule.

## License

MIT. See [`LICENSE`](LICENSE).

## Acknowledgements

Rules were distilled from ~150 real engineering sessions working with AI coding agents on a 300+ repository research portfolio. Every rule encodes at least one past incident; the regression fixtures frontload that history so future regressions fire immediately. The `sentinel:skip-file` marker was added specifically because the rule-documentation files themselves kept firing dogfooding BLOCKs — if there's a meta lesson it's "the tool that forbids bad patterns will itself need to mention those patterns; plan for that from day one."

---

**Star this repo** if you've ever pushed a `C:\Users\alice\...` path to production and wished something had caught it. Issues welcome — especially rule-proposal issues with a real incident attached.
