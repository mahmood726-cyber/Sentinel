# 2026-04-28 Rule Sweep — 2-Week Follow-Up Report

Generated: 2026-05-12T00:00:00Z

## (a) Sentinel rule drift

- **Snapshot**: 23 rules (6 YAML + 17 plugin) on 2026-04-28
- **Current**: 28 rules (6 YAML + 22 plugin)
- **Delta**: +5 / -0
- **New rules** (5 plugin, all added in window):
  - `rapidmeta_data_integrity.py` — P0, silent-shadowing trial-data bugs (2026-04-28)
  - `localstorage_key_collision.py` — P0, cross-file localStorage key reuse (2026-04-29)
  - `py_package_init_tracked.py` — P1, Python package `__init__` tracking (2026-04-29)
  - `license_compliance.py` — P1, GPL/AGPL deps in MIT repos (2026-04-29)
  - `cochrane_v65_invariants.py` — P1 WARN, Cochrane v65 API call-site invariants (2026-04-30)
- **Removed rules**: none
- **Commits touching rules in window** (12 commits, 2026-04-28 → 2026-05-09):

```
4d0f780 2026-04-28 feat(rules): P0-rapidmeta-data-integrity for silent-shadowing trial-data bugs
a36c00c 2026-04-29 feat(rules): P0-localstorage-key-collision for cross-file localStorage key reuse
b779e1a 2026-04-29 feat(rules): add P1-py-package-init-tracked
ca1db97 2026-04-29 feat(rules): P1-license-noncompliance — flag GPL/AGPL deps in MIT repos
661cd05 2026-04-30 feat(rules): P1-cochrane-v65-invariants WARN rule
b7d39e4 2026-04-30 fix(rule/cochrane-v65): require call-site presence, not just definition
e3eb4f0 2026-04-30 fix(rule/cochrane-v65): V8 accepts both engine-family naming styles
e6c3163 2026-05-06 refactor(rules): extract anchored skip-marker to sentinel/io/skip_marker.py
5fb4599 2026-05-06 fix(rule/hardcoded-path): exclude data/baselines/** like data/baseline_probes/**
61fbc20 2026-05-06 feat(rules): sentinel:skip-file marker support for parse-check rules
59398f2 2026-05-08 feat(rules): tighten scan to eliminate ~117K false-positive BLOCKs
0b3b9fd 2026-05-09 fix(P1-py-package-init-tracked): only flag tracked .py files
```

## (b) Preprint replication check

| # | Paper | Verdict | Justification |
|---|---|---|---|
| 1 | arXiv:2506.11022 (iterative-CVE) | HOLD | Queries: 'iterative code refinement security CVE LLM 2026', 'self-refine LLM security regression'. SCAFFOLD-CEGIS (2603.08520) extends with CEGIS-based mitigation but predates window (Mar 2026); arXiv:2604.10508 may extend but publication date within April unconfirmed; no contradictions found. |
| 2 | arXiv:2512.02445 (long-context-collapse) | HOLD | Queries: 'LLM agent long context refusal collapse 100k 2026'. General coverage confirms direction (Chroma "Context Rot" research, multiple 2026 practitioner posts) but no paper with a confirmed Apr 28–May 12 submission date found. |
| 3 | arXiv:2512.07497 (substitution-on-missing) | HOLD | Queries: 'LLM agent missing field substitution fabrication 2026', 'agent over-helpfulness required field'. General hallucination surveys returned; no specific in-window replication found. |
| 4 | arXiv:2509.25370 (first-error/AgentDebug) | HOLD | Queries: 'LLM agent first error trajectory cascading AgentDebug 2026'. Paper visible on OpenReview (under venue review); no new replication or extension paper confirmed in window. |
| 5 | arXiv:2603.29231 (long-horizon-decay) | PROMOTE | Queries: 'long-horizon LLM reliability duration 2026', 'pass@1 long-horizon decay'. arXiv:2605.02572 "Empirical Study of Horizon Length" (May 2026, definitively in window), arXiv:2604.24579 "Markov Chain Reliability for LLM Agents", and arXiv:2604.11978 "The Long-Horizon Task Mirage?" independently replicate horizon-dependent degradation — all consistent with original halving result. |
| 6 | arXiv:2601.11735 (NMA-multiplicative) | HOLD | Queries: 'multiplicative heterogeneity NMA 2026', 'NMA random effects multiplicative model'. Only the original paper and general NMA literature returned; no replication in window. |

## Recommended actions for next local session

1. **Update baseline snapshot** — register the 5 new plugin rules in the advanced-stats/lessons snapshot so the next sweep compares against 28 rules, not 23.
2. **PROMOTE arXiv:2603.29231 locally** — upgrade the long-horizon-decay rule from Medium to High confidence; arXiv:2605.02572, 2604.24579, and 2604.11978 constitute cross-method replication in the window.
3. **Confirm arXiv:2604.10508 date** — check arxiv.org directly to verify whether "How Many Tries Does It Take? Iterative Self-Repair…" was submitted after 2026-04-28; if yes, promote arXiv:2506.11022 (iterative-CVE) to High confidence.
4. **Audit false-positive fix** — the 2026-05-08 commit eliminated ~117K BLOCKs; verify locally that scan tightening did not suppress any previously flagged true positives before the next sweep.
5. **Watch cochrane_v65_invariants** — three rapid fix commits in two days (all 2026-04-30) indicate the rule is still being tuned; hold at WARN/P1 and do not promote to blocking enforcement until it stabilises over a full sweep cycle.
