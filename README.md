# Sentinel

Portfolio fail-closed integrity engine. Converts accumulated lessons into
executable rules that run pre-push.

## Status

**M1 (in progress)** — Rule engine + 3 rules.

## Quickstart

```
python -m pip install -e ".[dev]"
python -m pytest
python -m sentinel list-rules
python -m sentinel scan --repo /path/to/your/repo
python -m sentinel scan --portfolio --project-index /path/to/ProjectIndex
python -m sentinel explain P0-placeholder-hmac
```

## M1 Exit Criteria

- [ ] `sentinel list-rules` prints all three P0 rules.
- [ ] `sentinel scan --repo <clean>` exits 0 with no output to
      `sentinel-findings.md` or `STUCK_FAILURES.md`.
- [ ] `sentinel scan --repo <with-placeholder-hmac>` exits 1 and writes
      `STUCK_FAILURES.md`.
- [ ] `sentinel scan --portfolio --project-index <fixture-DRIFT>` exits 1
      and flags both `P0-path-not-exist` and `P0-registry-drift`.
- [ ] All three test layers green (`python -m pytest`).
- [ ] Coverage >= 90% on `sentinel/core` and `sentinel/registry`
      (`python -m pytest --cov`).

## Rule Authoring

- **YAML rules** — drop a `<id>.yaml` into `sentinel/rules/yaml/`.
  Required fields: `id`, `severity`, `description`, `pattern`, `source`,
  `fix_hint`.
- **Plugin rules** — drop a `<name>.py` into `sentinel/rules/plugins/`.
  Required attrs: `ID`, `SEVERITY`, `SOURCE`, `check(ctx) -> list[Verdict]`.
  Optional: `SCOPE` (default `"repo"`; use `"portfolio"` for
  registry-level rules).

## Design

See `docs/superpowers/specs/2026-04-14-sentinel-design.md`.
