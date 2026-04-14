---
project: Sentinel
date: 2026-04-14
author: Mahmood Ahmad (designed collaboratively with Claude)
status: design-approved
supersedes: none
location: C:\Sentinel\
---

# Sentinel — Portfolio Fail-Closed Integrity Engine

## Motivation

Across 129 coding sessions spanning 472 repos, the single highest-cost failure
mode has been **silent failures masquerading as success**:

- Placeholder HMAC signatures (`"SIG_RSA_SHA256_..."`) shipping as real crypto.
- Registry drift: `INDEX.md` claimed 517 projects while `restart-manifest.json`
  had 472 (45-project disagreement).
- Silent failure sentinels: `return "unknown_ratio"` on schema mismatch
  corrupted 465 MetaReproducer reviews before detection.
- Lifecycle promotion of projects whose paths no longer exist on disk
  (WinError 267).
- Hardcoded `C:\Users\...` paths shipped in GitHub Pages assets.
- `YOUR REWRITE` workbook sections touched despite "sacrosanct" policy.

These are not stylistic preferences; each one has a documented incident.
The accumulated ruleset lives in `C:\Users\user\.claude\rules\` as prose —
effective as reference, inert as enforcement.

Sentinel converts that prose into executable fail-closed contracts and runs
them at the exact moment a mistake would ship: pre-push.

## Non-Goals

- Not a new linter for language syntax (ruff/eslint already cover that).
- Not a replacement for `pytest` or project-specific test suites.
- Not a research tool or meta-analysis engine.
- Not an AI/LLM-driven code reviewer — rules are deterministic by design.
- Not a cloud service. Local-first, offline, no external dependencies.

## Architectural Decisions

| # | Decision | Chosen | Rejected alternatives |
|---|---|---|---|
| 1 | Flavor | Portfolio integrity engine consuming `lessons.md` as rules | Defect linter only; new research tool |
| 2 | Scope ordering | (iii) rule engine → (ii) depth on 5 repos → (i) breadth | breadth-first; depth-first |
| 3 | Integration posture | Wrap existing scripts as plugins | Absorb & replace; peer co-existence |
| 4 | Verdict model | Three tiers (BLOCK / WARN / INFO) | Binary PASS/FAIL; continuous 0–100 risk score |
| 5 | Trigger | CLI + pre-push git hook (chained, idempotent) | Manual only; cron sweep |
| 6 | Rule encoding | Hybrid — YAML for patterns, Python plugins for logic | Pure YAML; pure Python |

## Boundaries (What Sentinel Touches vs. Doesn't)

| System | Relationship | Mutation allowed |
|---|---|---|
| `C:\ProjectIndex\reconcile_counts.py` | Wrapped as Python plugin; stdout + exit code parsed | No |
| `C:\ProjectIndex\agent-records\restart-manifest.json` | Authoritative count source | No (read-only) |
| `C:\ProjectIndex\INDEX.md` | Read-only; findings go to `review-findings.md` | No |
| `C:\Users\user\push_all_repos.py` | Read-only repo list | No |
| `C:\E156\rewrite-workbook.txt` | **Never scanned**, never touched | No |
| Existing `.git/hooks/pre-push` | Chained; Sentinel runs first, hands off on exit 0 | Preserved |
| TruthCert HMAC signing | Verifies env-var keys, flags placeholder sigs | No (doesn't sign) |

## Non-Regression Guarantees (Executable Contracts)

1. Sentinel with zero rules = no-op, exits 0, no writes anywhere.
2. `reconcile_counts.py` standalone exit code unchanged whether invoked
   directly or via Sentinel plugin, for identical input.
3. Pre-push hook installer is idempotent; running it twice leaves one
   Sentinel hook in place and preserves any pre-existing hooks by chaining.
4. Sentinel never writes outside `C:\Sentinel\` and the target repo's
   `review-findings.md` / `STUCK_FAILURES.md`. Verified via filesystem
   watcher in CI.

## Module Layout

```
C:\Sentinel\
  sentinel/
    core/          # Runner, Verdict dataclass, Severity enum
    registry/      # Loads + validates rules from yaml/ and plugins/
    rules/
      yaml/        # Declarative rules, one .yaml per rule
      plugins/     # Python modules: def check(ctx) -> Verdict
    io/            # Repo scanner; review-findings.md / STUCK_FAILURES.md writers
    cli/           # scan, list-rules, install-hook, explain <rule-id>, bypass-log
    hook/          # Pre-push hook installer (chaining, idempotent)
  tests/
    contracts/     # Module-boundary schema tests
    fixtures/      # Minimal GOOD/BAD repos per rule
    regression/    # The 4 non-regression guarantees
  docs/
    superpowers/specs/  # This file
    dashboard/          # Offline HTML, no external CDN (per html-apps.md)
  logs/
    rule-errors.log
    bypass.log
```

## Rule Schemas

### YAML Rule

```yaml
id: P0-placeholder-hmac
severity: BLOCK            # BLOCK | WARN | INFO
description: Placeholder HMAC signatures shipping as real crypto.
pattern: 'SIG_RSA_SHA256_|signature_placeholder'
files: ['**/*.json', '**/*.py']
exclude: ['tests/**', 'fixtures/**', 'docs/superpowers/specs/**']
fix_hint: Replace with HMAC from env TRUTHCERT_HMAC_KEY.
source: lessons.md#cryptography-signing
```

Required fields: `id`, `severity`, `description`, `pattern`, `source`.
Missing any required field = BLOCK at load time, not runtime.

### Python Plugin

```python
# sentinel/rules/plugins/reconcile_counts.py
from sentinel.core import RepoContext, Verdict

ID = 'P0-registry-drift'
SEVERITY = 'BLOCK'
SOURCE = 'workflow.md#registry-reconciliation-gate'

def check(ctx: RepoContext) -> Verdict:
    # Implementation elided; body wraps `reconcile_counts.py` subprocess
    # and maps its exit code + stdout into a Verdict.
    raise NotImplementedError
```

Required module-level attributes: `ID`, `SEVERITY`, `SOURCE`, `check`.
Interface enforced by `test_plugin_interface.py`.

### Rule-ID Naming Convention

Prefixes `P0` / `P1` / `P2` denote **review priority**, not severity.
Severity is the `severity:` field. Most P0 rules are BLOCK and most P2
rules are INFO, but the coupling is not mechanical: a P1 rule may BLOCK
(e.g., workbook protection) when enforcement is warranted despite lower
review priority.

### Rule Scope (Repo vs. Portfolio)

Every rule declares `scope: repo | portfolio` (default `repo`).
- `scope: repo` rules fire on single-repo scans (pre-push hook path).
- `scope: portfolio` rules require the full registry (INDEX.md +
  manifest); they run only under `sentinel scan --portfolio` and during
  M3 nightly sweeps. They never fire during pre-push (too slow, out of
  scope for a single-repo push decision).

Of the MVP rules: rules 1, 4, 5, 6, 7, 8, 9, 10 are `repo`-scoped.
Rules 2 (`P0-path-not-exist`) and 3 (`P0-registry-drift`) are
`portfolio`-scoped and run only in the portfolio sweep, not pre-push.

### Uniform Verdict Record

```json
{
  "rule_id": "P0-placeholder-hmac",
  "severity": "BLOCK",
  "repo": "C:/Projects/shifaa",
  "file": "shifaa/bundles/cert_v1.json",
  "line": 42,
  "detail": "...",
  "fix_hint": "...",
  "source": "lessons.md#cryptography-signing",
  "timestamp": "2026-04-14T10:23:00Z"
}
```

Runner never branches on rule type; only on verdict severity.

## Data Flow (Pre-Push Invocation)

```
git push
  -> .git/hooks/pre-push (Sentinel's chained hook)
  -> sentinel scan --repo <CWD> --trigger pre-push
  -> registry loads rules (yaml/ + plugins/)
  -> for each rule: check(ctx) -> Verdict
  -> collect + sort by severity
  -> any BLOCK  : write STUCK_FAILURES.md, print summary, exit 1
     any WARN   : append review-findings.md, exit 0
     INFO only  : log, exit 0
  -> hand off to next chained hook on exit 0
```

## MVP Rule Set (10 Rules)

| # | Rule ID | Severity | Source |
|---|---|---|---|
| 1 | `P0-placeholder-hmac` | BLOCK | lessons.md#cryptography-signing |
| 2 | `P0-path-not-exist` | BLOCK | workflow.md#exact-path-contract |
| 3 | `P0-registry-drift` | BLOCK | workflow.md#registry-reconciliation-gate |
| 4 | `P0-claude-config-committed` | BLOCK | CLAUDE.md#config-safety |
| 5 | `P0-hardcoded-local-path` | BLOCK | lessons.md#code-quality |
| 6 | `P1-unpopulated-placeholder` | WARN | html-apps.md#safety-checks |
| 7 | `P1-silent-failure-sentinel` | WARN | lessons.md#integration-contracts |
| 8 | `P1-script-in-template-literal` | WARN | lessons.md#javascript-html |
| 9 | `P0-workbook-rewrite-touched` | BLOCK | CLAUDE.md#workbook-protection |
| 10 | `P2-progress-md-not-gitignored` | INFO | workflow.md#savepoint-discipline |

Rule 9 is the mechanical enforcement of the `YOUR REWRITE` sacrosanct policy
currently kept only in prose.

Per the rule-scope model above, M1's pre-push path exercises rules 1, 4, 5,
6, 7, 8, 9 on the single repo being pushed. Rules 2 and 3 (portfolio-scoped)
run under `sentinel scan --portfolio` and light up in M3's nightly sweep.

## Error Handling (Fail-Closed Semantics)

| Failure mode | Response | Exit |
|---|---|---|
| Rule `check()` raises | Log stack; synthetic BLOCK verdict | 1 |
| Manifest missing / unreadable | `P0-registry-drift` BLOCK with `detail="manifest unreadable"` | 1 |
| Wrapped subprocess hangs | Hard timeout (120s smoke, 300s verify); kill; synthetic BLOCK | 1 |
| Sentinel itself crashes | Hook wrapper still aborts push | 1 |
| Zero rules loaded | BLOCK — empty Sentinel is misconfigured | 1 |
| Malformed YAML rule file | BLOCK at load time, before any scan runs | 1 |

### Bypass Escape Hatch

`SENTINEL_BYPASS=1 git push` skips Sentinel. Logged to
`C:\Sentinel\logs\bypass.log` with git user, timestamp, repo, ruleset hash.
Surfaces on dashboard for weekly hygiene review. Deliberately visible —
circumventing a broken tool should be traceable, not invisible.

## Testing Strategy

### Layer 1 — Contract Tests (`tests/contracts/`)
- `test_yaml_rule_schema.py`: every YAML file parses into valid `Rule`
  dataclass; missing required field raises `KeyError` with expected-vs-got diff.
- `test_plugin_interface.py`: every plugin exposes `ID`, `SEVERITY`, `SOURCE`,
  `check(ctx) -> Verdict`. Interface, not content.
- `test_verdict_schema.py`: verdicts from both rule types validate against
  one JSON schema.

### Layer 2 — Fixture Repos (`tests/fixtures/`)
Two fixtures per rule (20 total for MVP):
- `fixture_<rule>_BAD/`: scan returns BLOCK for that rule_id.
- `fixture_<rule>_GOOD/`: scan returns zero verdicts.

Positive-and-negative coverage, both always. A BLOCK that never fires and a
BLOCK that always fires are equally broken.

### Layer 3 — Non-Regression Tests (`tests/regression/`)
Executable versions of the four guarantees:
- `test_reconcile_exit_code_unchanged.py`
- `test_zero_rules_noop.py`
- `test_hook_chaining_idempotent.py`
- `test_no_writes_outside_scope.py` (filesystem watcher)

### Release Gate
- All three layers green.
- `pytest --cov` >= 90% on `core/` and `registry/`.
- Pass/fail counts printed, never "done" without them (per testing.md).

## Rollout Milestones

### M1 — Rule Engine + 3 Rules (~1 week)
- `core/`, `registry/`, `io/`, `cli/` scaffolding.
- YAML loader + Python plugin loader + uniform `Verdict`.
- Rules 1 (`P0-placeholder-hmac`, repo-scoped),
  2 (`P0-path-not-exist`, portfolio-scoped),
  3 (`P0-registry-drift`, portfolio-scoped, wrapping `reconcile_counts.py`).
- **Exit criteria:** `sentinel scan --repo C:\Projects\shifaa` exercises
  rule 1 cleanly (or flags real issues). `sentinel scan --portfolio`
  exercises rules 2 and 3 cleanly. Contract tests + 6 fixtures green.

### M2 — Depth on 5 High-Stakes Repos (~1 week)
- Target repos (TruthCert-adjacent, highest blast-radius):
  1. `C:\Projects\shifaa` (TruthCert, 5 papers)
  2. `C:\MetaAudit` (BMJ target)
  3. `C:\Models\MES` (BMJ + F1000)
  4. `C:\overmind` (orchestrator)
  5. `C:\cardiosynth` (134 tests, living engine)
- Rules 4–9 added.
- Pre-push hook installer + chaining contract test.
- **Exit criteria:** hook installed on all 5; one real BLOCK event caught
  and fixed in the wild.

### M3 — Portfolio Breadth (~1 week)
- Rule 10 added.
- Offline dashboard (`C:\Sentinel\dashboard\index.html`, no external CDN
  per `html-apps.md`).
- Installer script iterates `push_all_repos.py` repo list.
- Nightly read-only portfolio sweep (JSON summary; no hook changes).
- **Exit criteria:** `reconcile_counts.py` subsumed as plugin; bypass log
  reviewable; all active repos scanned; dashboard live.

## Open Questions (Deferred Past M3)

- Should INFO-tier rules eventually graduate to WARN based on recurrence?
- Ed25519 vs. HMAC for `Verdict` log-integrity signatures?
- Rule inheritance (project-specific overrides for generic lessons)?

## Integration with E156 Workflow

Sentinel must never interfere with the E156 micro-paper pipeline:
- Scanning `C:\E156\` excludes `rewrite-workbook.txt` entirely.
- Rule 9 (`P1-workbook-rewrite-touched`) hard-blocks any diff touching
  `YOUR REWRITE` lines. Enforced via `git diff --unified=0` parsing.
- E156 deploy scripts (`C:\E156\scripts\deploy_all.py`) unmodified.

## References

- `C:\Users\user\CLAUDE.md`
- `C:\Users\user\.claude\rules\lessons.md`
- `C:\Users\user\.claude\rules\workflow.md`
- `C:\Users\user\.claude\rules\testing.md`
- `C:\Users\user\.claude\rules\html-apps.md`
- `C:\Users\user\.claude\rules\advanced-stats.md`
- `C:\ProjectIndex\reconcile_counts.py`
- `C:\ProjectIndex\agent-records\restart-manifest.json`
