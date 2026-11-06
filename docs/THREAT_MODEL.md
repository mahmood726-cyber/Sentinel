# Sentinel — Threat Model

<!-- sentinel:skip-file — threat-model doc cites canonical paths as examples -->

**Scope:** the Sentinel rule engine (`C:\Sentinel\`), its pre-push hook installations, and the data-plane integration with Overmind. Last reviewed: 2026-04-15.

**Version:** 1.0 (initial). No external audit has occurred.

---

## 1. What Sentinel defends

### Assets
1. **Enforcement integrity** — the guarantee that a Sentinel BLOCK actually prevents the push it fired on.
2. **Findings integrity** — the contents of `STUCK_FAILURES.jsonl` + `sentinel-findings.jsonl`. Downstream (Overmind) trusts these.
3. **Bypass-log integrity** — `~/.sentinel-logs/bypass.log`. If forged or wiped, enforcement visibility is lost.
4. **Rule inventory** — the set of YAML + plugin rules in `sentinel/rules/`. A silently-deleted rule is a silent policy regression.
5. **Memory confidentiality** (secondary) — `.claude/projects/` directories in scanned repos. Sentinel excludes these from scans; it is not the primary defender.

### Trust boundaries
| Zone | Trust level | Boundary |
|---|---|---|
| User's own code | **Trusted input** — Sentinel scans it assuming the user owns it | Defined by `git ls-files --cached --others --exclude-standard` on the scanned repo |
| User's environment variables | **Trusted at invocation** — env vars at git-push time govern behavior | Shell process of `git push` |
| `~/.sentinel-logs/bypass.log` | **Append-only**, trusted as written by Sentinel's own hook | Filesystem permissions on user's home |
| Sentinel rule files | **Trusted** — treated as ground truth | `sentinel/rules/**` must not be committed via Sentinel's own rules (GLOBAL_EXCLUDES) |
| Remote code being fetched/pulled | **Untrusted** — but Sentinel doesn't scan fetched code, only outgoing pushes | N/A to Sentinel |
| Parallel agent tools (Claude/Gemini/Codex) | **Partially trusted** — may make mistakes, but not malicious | Enforced by pre-push rules catching common-class errors |

---

## 2. Attacker profiles

Sentinel is **not designed against adversarial attackers with code-exec on the user's machine.** At that point, the attacker has fully won — they can edit rules, bypass hooks, or replace Sentinel outright. Sentinel is a **quality gate**, not a security boundary.

Realistic threat models:

1. **The user making a mistake.** (Dominant case.) Accidentally committing a hardcoded path, placeholder HMAC, committed `.claude/` config, etc. — Sentinel's primary purpose.
2. **An AI agent making a mistake.** (Secondary case.) Claude/Gemini/Codex writes code that violates policy. Sentinel catches pre-push.
3. **A forgetful user silently bypassing enforcement.** (Drift case.) Uses `SENTINEL_BYPASS=1` habitually until enforcement is effectively off. Defended by the nightly bypass-log aggregator (wired 2026-04-15).
4. **A malicious agent trying to hide a violation in a way that evades Sentinel.** (Edge case.) E.g. embedding `sentinel:skip-file` in an attacker-controlled file. Discussed below.

Out of scope:
- Physical access to the machine
- Compromised Python interpreter
- Malicious `git` binary replacement
- Sentinel being scanned by untrusted third-party Sentinel installations (Sentinel is meant to be run on code you own)

---

## 3. Known weaknesses and mitigations

### 3.1 Skip-file marker abuse

**Vector:** The `sentinel:skip-file` marker is a first-1KB substring match (see `sentinel/registry/yaml_loader.py::_file_has_skip_marker`). A file containing the literal string in its first 1024 bytes is excluded from ALL rules.

**Attack:** A malicious or sloppy agent could embed the marker in a file that contains a real violation (e.g. a hardcoded path + the marker as a fake comment), bypassing Sentinel.

**Mitigation (current):**
- The marker must appear in the first 1KB — deep-hidden markers don't count (`test_skip_marker_must_be_in_first_1kb` regression test).
- Code review (human or agent) should flag any `sentinel:skip-file` addition on a file that shouldn't need it.
- Marker is a documented convention, not a secret — easy for reviewers to grep for.

**Accepted risk:** A targeted malicious insertion IS possible and will succeed. This is acceptable because:
1. Sentinel scans user-owned code; the user controls what gets marked.
2. The marker appearing in a PR diff is highly visible in review.
3. The alternative (no skip capability) would kill the tool — rule documentation files fire dogfooding BLOCKs without it.

**Hardening options (deferred):**
- Require a paired commit note explaining why a file is skip-marked
- List all skip-marked files in the nightly report (visibility)
- Rule-specific skip markers (e.g. `sentinel:skip-rule:P0-hardcoded-local-path`) — narrower blast radius

### 3.2 Bypass log not alerted

**Vector:** `SENTINEL_BYPASS=1 git push` writes to `~/.sentinel-logs/bypass.log` but, until 2026-04-15 commit `ec8a750`, nothing read it. A user could bypass daily for months without notice. Enforcement would be silently off.

**Mitigation (current, 2026-04-15):**
- `overmind.integrations.bypass_log_aggregator.collect()` reads the log, buckets by repo, surfaces the top repeat-bypassers over a configurable window (default 7 days).
- `scripts/nightly_verify.py` calls `collect_bypass_findings()` and renders a "Sentinel Bypass Log" section when nonzero.
- Render is zero-noise: empty log → no section in the report. Only noise is signal.

**Accepted risk:** A user can edit or delete `bypass.log` directly. This is tolerated — we're protecting against forgetfulness, not active deception. If a user deliberately edits the log to hide bypasses, they've made a conscious decision that Sentinel can't override.

**Hardening options (deferred):**
- Append-only file attribute (`chattr +a` on Linux; no clean Windows equivalent)
- HMAC-signed log entries (overkill for quality-gate purposes)
- Store copies elsewhere (e.g. replicate to Overmind SQLite) — done partially by aggregator reads

### 3.3 Env-var override trust boundary

**Vector:** Today's session added several env-var overrides:
- `OVERMIND_DISCOVER_IMPORT_ROOT` (sentinel_aggregator.py)
- `OVERMIND_PYTHON` (nightly_verify.bat)
- `DRMA_HUGE_CSV` (ProportionFirstPrinciples)
- `SENTINEL_HOME_CONFIG_ROOT` (check_rules_sync.py)
- `SENTINEL_MEMORY_INDEX` (check_memory_drift.py)
- `TRUTHCERT_HMAC_KEY` (lessons.md enforces this for placeholder-hmac rule)

**Attack:** An attacker with env-var control (e.g. Task Scheduler hijack, malicious `.bashrc` edit) could redirect Sentinel's scan root, discovery root, or verification path — causing it to scan a benign directory instead of the actual code, or to trust a fake aggregator path.

**Mitigation (current):**
- Each env var has a **safe default** rooted in `Path.home()`. Unsetting the env var returns to the default.
- Overrides are documented at the point of use.
- None of the env vars permit direct code execution — they're all path or version strings.

**Accepted risk:** At the attack threshold where env-var injection is available, the attacker already has code-exec on the user's account (via the injection vector itself). Sentinel doesn't defend against that.

**Hardening options (deferred):**
- Validate env-var contents at use (e.g. path must resolve + be in a user-writable tree)
- Log every env-var override at scan time for audit trail
- Refuse to scan if env vars are set in a way that would redirect to non-home paths

### 3.4 JSON `$sentinel` marker convention

**Vector:** `claude-settings.json` and `manifest.json` carry `"$sentinel": "sentinel:skip-file — ..."` as an unknown top-level key. The convention relies on JSON consumers (Claude Code, Sentinel itself) to ignore unknown keys.

**Attack:** A consumer that DOES process unknown keys (or a future tool that repurposes `$sentinel`) could treat the marker string as something semantically meaningful — e.g. a rule ID, a file path.

**Mitigation (current):**
- The `$sentinel` key is namespaced with `$` prefix, a JSON-Schema convention for metadata.
- Value is a human-readable sentence that contains the `sentinel:skip-file` marker substring, which is what Sentinel matches on.
- No tool we currently use acts on unknown JSON keys in these files.

**Accepted risk:** If a future tool processes `$sentinel` as a typed field, behavior is unspecified. We accept this — the mitigation is to rename before adopting such a tool.

**Hardening options (deferred):**
- Move the marker to a companion `.sentinel-skip` sidecar file instead of embedded JSON key
- Publish a mini-spec for the `sentinel:skip-file` marker so tools don't conflict

### 3.5 Memory portability

**Vector:** `.claude/projects/<slug>/memory/` (where slug = `C--Users-user` on this machine) is gitignored by design. If the user reinstalls Claude Code, switches machines, or loses the home directory, all memory is lost. Archived memory (in `memory/archived/`) lives in the same gitignored tree and is equally lost.

**Attack:** Not adversarial — this is a **data-loss risk**, not a confidentiality or integrity risk.

**Mitigation (current):**
- MEMORY.md index is small enough (47 lines) to reconstruct from tracked mirrors.
- Project memory files contain nothing agents couldn't re-derive from tracked code + `git log` within a few sessions.
- Critical state (INDEX.md, reconcile_counts.py output, workbook) lives in dedicated tracked registries, not memory.

**Accepted risk:** Loss of `.claude/projects/` means a ~1-session rebuild cost, not a permanent loss. The confidentiality benefit (memory stays off GitHub) outweighs the portability cost at the user's threat model.

**Hardening options (deferred):**
- Encrypted backup of the memory tree to a user-controlled remote (e.g. personal S3 with KMS)
- Selective export: a script that copies memory/*.md → a tracked `memory-snapshot/` directory after scrubbing sensitive fields
- Manual ritual: "every 30 days, zip memory/ to an offline drive"

### 3.6 Git-backed file inventory can fail incomplete (2026-11-05)

**Vector:** Plugin scans use `git ls-files -z` to bound file discovery
inside Git worktrees. Returning an empty iterable on Git command failure
allowed plugin rules to report no findings without inspecting any tracked
files. Converting that failure into an ordinary BLOCK finding is also
insufficient in a hook configured in warn mode.

**Mitigation (draft PR #6):**
- `iter_repo_files` raises `GitFileEnumerationError` for failed or
  undecodable Git listings, not an empty successful result.
- The plugin wrapper propagates this specific failure into the scan CLI's
  internal-error contract (exit 10). The pre-push hook refuses all internal
  errors even in warn mode.
- The YAML-rule scanner also recognizes directory-based and linked
  (`.git` file) worktrees. A failed, timed-out or undecodable Git listing
  raises `GitFileEnumerationError` instead of falling back to a filesystem
  walk; this keeps the hook's fatal exit-10 contract intact for YAML BLOCK
  rules and avoids scanning irrelevant ignored files.
- There is **no** `rglob` fallback inside a recognized Git worktree:
  an unbounded walk of a user home directory could stall the hook again.
  Ad-hoc non-Git roots retain the bounded-by-caller legacy traversal.

- Git-backed plugin enumeration now raises an internal scan error if
  `Path.is_file()` raises on a tracked, non-excluded candidate, rather
  than silently skipping a possible BLOCK. Files excluded before inspection
  and ordinary deleted worktree paths retain their prior behavior.
- YAML scanning now checks `stat()` explicitly for Git-listed candidates:
  inaccessible file status, header or text reads abort with a fatal internal
  error instead of silently omitting a potential BLOCK. The diagnostic
  suppresses underlying private filesystem exception details. A genuinely
  missing tracked worktree path (e.g., an unstaged deletion) remains a
  legitimate skip, and clean/ignored files do not cause new findings.

**Additional guarded path:** `P1-leaked-secret` now raises the fatal
`GitFileEnumerationError` if a candidate cannot be inspected after discovery,
so read/status failures cannot silently suppress a credential BLOCK; explicitly
excluded documentation remains out of scope. The diagnostic does not propagate
private filesystem errors. Synthetic negative and legitimate controls are in
`test_rule_leaked_secret.py`.

**Additional guarded path:** `P0-e156-placeholder-leak` now treats
filesystem status or read failures on its root-level `students.html` and
`rewrite-workbook.txt` candidates as fatal scan errors rather than a clean
scan. Missing artifacts remain optional, and unrelated files are untouched.
The internal-error diagnostic does not chain private OS exception messages.
Synthetic failure and valid-artifact controls live in
`test_rule_e156_placeholder_access.py`.

**Additional guarded path:** `P0-unsafe-eval-exec` now aborts on a
file-content read error after a Python candidate has entered its scan
inventory. Previously the `except OSError: continue` branch could silently
miss a dynamic `eval`/`exec` BLOCK. The scanner now returns an internal
error even in warn-mode hooks, without chaining private filesystem messages.
`test_rule_unsafe_eval_access.py` covers an inaccessible synthetic BLOCK,
a readable BLOCK, a literal-only valid file, and an excluded unreadable
directory.

**Additional guarded path:** `P1-py-parse-check` now treats a
file-content read error for a discovered Python candidate as a fatal scanner
error (exit 10), rather than an ordinary BLOCK verdict that a warn-mode
hook could allow. A readable syntax error continues to produce its existing
BLOCK verdict. Synthetic controls cover an inaccessible candidate,
valid Python, an actual syntax BLOCK and an excluded unreadable virtualenv
file in `test_rule_py_parse_access.py`. The original OS exception is
not exposed in the formatted traceback.

**JavaScript parser runtime completeness (5 November 2026):**
The BLOCK-tier `P1-js-parse-check` previously returned clean when the
`node` executable was unavailable, and returned an ordinary BLOCK on
parser timeout (which warn-mode hooks can allow). A parser launch error
could similarly become an ordinary plugin BLOCK. For a non-excluded JS
candidate, unavailable Node, launcher errors, undecodable output and
timeouts now raise a sanitized fatal scan error (CLI exit 10). A scan
with no applicable JavaScript candidates, including correctly excluded
or explicitly skip-marked files, remains clean. Actual syntax errors
still emit the rule's ordinary BLOCK. Synthetic tests in
`test_rule_js_parser_runtime.py` cover absent Node, launch failure,
timeout, clean-code and syntax-failure cases. This does not guarantee
the external Node parser's correctness or attest that every subprocess
nonzero status is a syntax error.

**Additional guarded path:** `P1-script-close-in-template` now treats a
discovered HTML candidate's file-status or text-read error as a fatal
scanner error instead of silently skipping a possible BLOCK. An ordinary
readable literal `</script>` inside a JavaScript template continues to
produce the existing BLOCK verdict. Valid split-token templates and
ignored vendor directories remain clean. The underlying OS exception is
not chained into diagnostics. Synthetic test-first coverage lives in
`test_rule_script_close_access.py`.

**Additional guarded path:** `P1-nullish-or-mixed` now aborts when a discovered
JavaScript or inline-HTML candidate cannot be inspected because a status or
text-read operation raises `OSError`. Previously both code paths silently
continued, potentially missing a syntax BLOCK. The fatal scan error is not
warn-mode-downgradable (CLI exit 10) and does not chain private OS diagnostics.
Synthetic negative, readable-BLOCK, valid-grouping and excluded-directory
controls are in `test_rule_nullish_access.py`; minified/oversized-file policy
and the rule's BLOCK severity are unchanged.

**Additional guarded path:** `P0-hmac-compare-eq` now treats an
unreadable Python candidate as a fatal, non-warn-downgradable scanner
error rather than silently skipping a possible crypto-comparison BLOCK.
The underlying filesystem exception is not chained into the public
diagnostic. Synthetic tests in `test_rule_hmac_compare_access.py`
cover an inaccessible candidate, a readable BLOCK, a legitimate
constant-time comparison and an excluded unreadable directory. This
does not introduce signing or change crypto functionality.

**Nested tracked-file coverage (5 November 2026):** Git's ordinary
`test_*.py` pathspec matches the repository root but can omit
`tests/test_*.py`. Sentinel now supplies recursive Git glob pathspecs
(`:(glob)**/test_*.py`) to make tracked-file enumeration consistent
with the non-Git `rglob` fallback. This prevents a tracked nested
duplicate test module from silently escaping the
`P1-test-module-collision` BLOCK rule. Synthetic regressions cover
the root-plus-nested collision, correctly packaged duplicates, and
excluded/untracked candidates. This does not expand scanning to
untracked or excluded files.

**Tracked package-marker integrity (5 November 2026):** A worktree-local
but untracked `__init__.py` marker is not present after push and must not
silence a `P1-test-module-collision` BLOCK. The rule now uses the bounded
tracked-file inventory for package markers rather than only checking the
working-tree filesystem. This context lookup deliberately ignores the
`--diff` path filter: unchanged, tracked package markers must still keep
valid distinct modules clean. Changed test files produce differential verdicts while all tracked
test modules remain available as comparison context; exclusions remain enforced. Synthetic tests cover untracked
markers that previously hid a BLOCK and tracked markers in a filtered,
legitimate package layout. Git enumeration failures retain the fatal
scan-error contract.

**Ancestor package identity (5 November 2026):** A test module's
import name is the contiguous path of tracked Python packages above it,
not merely its basename plus immediate parent. For example, tracked
`north/sub/__init__.py` and `south/sub/__init__.py` cannot distinguish
two `test_example.py` files when the outer `north/` and `south/`
directories lack tracked `__init__.py` markers: both resolve to
`sub.test_example` under pytest's default prepend importer. Sentinel
now compares complete resolved import names and reports a BLOCK for both.
Distinct fully packaged modules, and distinct inner package names despite
missing ancestors, remain clean. The deterministic tests use newly
created Git fixtures and do not process publication data.

**Differential test-collision completeness (6 November 2026):** A changed
tracked `test_*.py` module can collide with an unchanged tracked test
module. Candidate enumeration limited to changed files misses this BLOCK,
even when the changed module is valid Python. The collision rule now reads
the bounded tracked test inventory as context, but under `--diff` reports
only changed colliding test files, so unrelated pushes are not blocked by
pre-existing test collisions. Changed-only BLOCK, unrelated clean push,
both-changed BLOCK and correctly packaged clean-push cases are covered by
deterministic synthetic Git fixtures. A package-marker-only change that
alters another file's import identity is a separate unverified case.

**Remaining limitations:** Other plugin/rule-specific read handlers may
still skip inaccessible files. Non-Git ad-hoc roots retain filesystem
traversal and its pre-existing path-discovery behavior. These are not
certified by the YAML or E156 placeholder controls.

---

## 4. Attack surfaces explicitly NOT defended

| Surface | Why Sentinel doesn't cover it |
|---|---|
| The Python interpreter Sentinel runs on | Trusted infrastructure. Compromise = game over for many things, not just Sentinel. |
| The `git` binary | Same. |
| GitHub remote (push target) | GitHub handles its own auth. Sentinel is pre-push. |
| `.git/hooks/pre-push` being removed | Detectable by checking for `SENTINEL_MARKER` banner; not currently audited on a schedule. |
| Malicious rule files added to `sentinel/rules/` | Sentinel can't scan its own rule dir (`GLOBAL_EXCLUDES` excludes it). Rule-authoring is a trusted operation. |
| Supply chain (pip dependencies, yaml library RCE) | Dependency pinning in pyproject.toml + `yaml.safe_load` usage. Not separately audited. |
| Untrusted YAML rule files from external sources | Assumed not to exist — all rules come from this repo. If that changes, YAML source origin must be re-evaluated. |

---

## 5. Known bypass mechanisms (documented, intentional)

| Bypass | Intent | Visibility |
|---|---|---|
| `SENTINEL_BYPASS=1 git push` | Emergency escape valve when a false-positive is blocking legitimate work | Logged to `bypass.log` + surfaced in nightly (§3.2) |
| `sentinel:skip-file` marker | Rule-doc files and auto-gen content that would produce false positives | Per-file, visible in diff; see §3.1 |
| Per-rule YAML `exclude` list | Targeted path exclusions for known-legitimate exceptions | Visible in the rule YAML itself |
| `scope: portfolio` on portfolio-scope rules | Skipped in pre-push; run only on `scan --portfolio` | By design, not a bypass |

---

## 6. What triggers a review of this document

This threat model should be revisited if any of the following land:

- A Sentinel rule is added that scans non-code artifacts (images, binaries, PDFs) — supply chain implications
- Sentinel is deployed to a repo owned by a party other than the user — the "trusted input" assumption flips
- A new env-var is added to the public API — §3.3 expands
- The skip-file marker convention is changed — §3.1 must be reviewed
- An external audit is performed (ref. 2026-04-15 recommendation to get one)
- Sentinel is open-sourced with external contributors — dependency / rule-origin assumptions shift

---

## 7. Out-of-scope follow-ups (captured for later sessions)

1. **Pre-push hook tamper detection**: a monthly job that verifies the SENTINEL_MARKER banner is still in `.git/hooks/pre-push` across the ≥10 hook-installed repos.
2. **Rule-inventory snapshot**: a weekly test that asserts the rule count and IDs haven't silently changed.
3. **Formal fuzz testing** of the skip-marker substring match (can an edge-case byte sequence cause a false skip?).
4. **External review** — the single most valuable follow-up. This document is internally consistent but has never been stress-tested by someone outside the user's mental model.

---

**Review cadence:** re-read at every major Sentinel release or every 6 months, whichever is sooner.
