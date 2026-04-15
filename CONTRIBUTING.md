# Contributing to Sentinel

Thanks for your interest. Sentinel is in its first public release and the bar for changes is straightforward:

## The short version

1. **Rules need real incidents behind them.** A rule without a regression fixture is a theory. Every rule in `sentinel/rules/` has at least one test in `tests/regression/test_historical_incidents.py` encoding the actual content that caused the bug. Proposed rules should come with their motivating incident — even if the "incident" is from a paper, blog post, or postmortem.

2. **False positives are more expensive than false negatives.** A rule that fires on legitimate code erodes trust in the whole tool. Before proposing a new rule, think about what it would fire on in this repo, in Semgrep's repo, in the top 10 Python repos on GitHub. If any legitimate pattern matches, narrow the rule.

3. **Tests first, for real.** This project uses test-driven development for rule changes. Write the regression test first (it fails); write the rule (it passes); ship both in the same PR.

## Rule proposals

Open an issue with:
- One-sentence description of the bug class
- A real minimal reproducer (actual code that caused the bug, not a synthetic example — `git log -p` to find it if needed)
- Why existing rules don't catch it
- One sentence on the fix hint

From there we can discuss whether it's a YAML rule (pattern-based) or a Python plugin (needs cross-file / state / non-regex logic).

## Code style

- Python 3.11+, type hints on public API
- No external dependencies beyond what's already in `pyproject.toml` for new rules
- `yaml.safe_load` only (never `yaml.load`)
- New plugin rules follow the pattern in `sentinel/rules/plugins/path_not_exist.py`

## Testing

```bash
pip install -e ".[dev]"
pytest                              # all 195+ tests
pytest tests/regression             # historical incident corpus
pytest tests/unit/test_rule_*       # per-rule unit tests
```

All tests must pass. New rules require at least one unit test (positive + negative case) and at least one regression-corpus test (real incident).

## Pull requests

- Small PRs per concern. A PR adding a new rule should not also refactor unrelated code.
- Commit messages should explain the WHY, not the WHAT (the diff shows the what).
- If your change touches `docs/THREAT_MODEL.md` assumptions (e.g. adding an env var, new skip convention, scanning new file types), update the threat model in the same PR.

## Security

If you find a way to make Sentinel silently miss a violation that should fire, please open a private issue (email address on author's GitHub profile) rather than a public PR. The threat model explicitly notes Sentinel is a quality gate, not a security boundary, but silent-miss bugs are still worth triaging privately first.

## Roadmap items that are open for PRs

- Rule-specific skip markers (e.g. `sentinel:skip-rule:P1-unpopulated-placeholder`) instead of the current all-rules `sentinel:skip-file`
- Pre-push hook tamper detection (monthly job verifying the SENTINEL_MARKER banner)
- Fuzz testing of the skip-marker substring match
- More regression fixtures — the corpus is at 17, target ~50 to match Semgrep-class authority

Thanks again.
