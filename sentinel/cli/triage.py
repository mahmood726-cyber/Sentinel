"""`sentinel triage` subcommand — optional LLM precision layer over verdicts.

Runs OUTSIDE the blocking pre-push path. Takes verdicts (from a saved
`sentinel scan --json` file, or by scanning a repo fresh), asks an LLM to judge
each BLOCK in context, and reports keep / downgrade / likely_fp. With --apply it
emits a new verdict set with confidently-false BLOCKs demoted to WARN
(downgrade-only; never deletes). No-op (exit 0) if no backend is configured.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from typing import List

from sentinel.core import Verdict
from sentinel import triage as triage_mod

EXIT_USER_ERROR = 2


def add_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "triage",
        help="LLM precision pass over verdicts (downgrade likely false BLOCKs). "
             "Offline/optional; never runs in the pre-push hook.",
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--scan", type=Path,
                       help="Path to a `sentinel scan --json` output file")
    group.add_argument("--repo", type=Path,
                       help="Scan this repo fresh, then triage")
    p.add_argument("--repo-root", type=Path, default=None,
                   help="Base dir for resolving relative file paths when --scan "
                        "was produced elsewhere (default: each verdict's repo)")
    p.add_argument("--context", type=int, default=30,
                   help="Lines of code context around each finding (default 30)")
    p.add_argument("--min-confidence", type=float, default=0.8,
                   help="Min model confidence to downgrade with --apply (default 0.8)")
    p.add_argument("--all", action="store_true",
                   help="Triage WARN/INFO too, not just BLOCK")
    p.add_argument("--apply", action="store_true",
                   help="Emit a new verdict set with confident FPs demoted BLOCK->WARN")
    p.add_argument("--out", type=Path, default=None,
                   help="Write output JSON here instead of stdout")
    p.add_argument("--json", action="store_true",
                   help="Emit triage results as JSON (implied by --apply)")
    p.set_defaults(func=_run)


def _run(args: argparse.Namespace) -> int:
    # 1. obtain verdicts
    if args.repo:
        if not args.repo.is_dir():
            print(f"[Sentinel] error: --repo not a directory: {args.repo}", file=sys.stderr)
            return EXIT_USER_ERROR
        verdicts = triage_mod.scan_repo(args.repo)
        repo_root = args.repo
    else:
        if not args.scan.is_file():
            print(f"[Sentinel] error: --scan file not found: {args.scan}", file=sys.stderr)
            return EXIT_USER_ERROR
        verdicts = triage_mod.load_verdicts_json(args.scan)
        repo_root = args.repo_root

    # 2. backend (auto-detect; no-op if none)
    name, call = triage_mod.detect_backend()
    if call is None:
        print("[Sentinel] triage: no LLM backend available "
              "(set ANTHROPIC_API_KEY, or run a local ollama). Triage is a no-op; "
              "the deterministic scan result is unchanged.")
        return 0

    results = triage_mod.triage_verdicts(
        verdicts, call, repo_root=repo_root,
        context_lines=args.context, only_blocks=not args.all)

    # 3. apply or report
    if args.apply:
        new_verdicts = triage_mod.apply_triage(
            verdicts, results, min_confidence=args.min_confidence)
        payload = {"verdicts": [v.to_dict() for v in new_verdicts]}
        _emit(payload, args.out)
        demoted = sum(1 for o, n in zip(verdicts, new_verdicts)
                      if o.severity != n.severity)
        print(f"[Sentinel] triage ({name}): demoted {demoted} BLOCK->WARN "
              f"(min-confidence {args.min_confidence})", file=sys.stderr)
        return 0

    if args.json or args.out:
        _emit({"backend": name, "triage": [r.to_dict() for r in results]}, args.out)
        return 0

    _print_report(name, results)
    return 0


def _emit(payload: dict, out: Path | None) -> None:
    text = json.dumps(payload, indent=2)
    if out:
        out.write_text(text, encoding="utf-8")
        print(f"[Sentinel] wrote {out}", file=sys.stderr)
    else:
        print(text)


def _print_report(backend: str, results: List[triage_mod.TriageResult]) -> None:
    keep = [r for r in results if r.verdict == "keep"]
    down = [r for r in results if r.verdict == "downgrade"]
    fp = [r for r in results if r.verdict == "likely_fp"]
    print(f"[Sentinel] triage ({backend}): "
          f"{len(results)} examined | keep={len(keep)} "
          f"downgrade={len(down)} likely_fp={len(fp)}")
    for r in down + fp:
        loc = f"{r.file}:{r.line}" if r.file and r.line else (r.file or "(repo-wide)")
        print(f"  [{r.verdict} {r.confidence:.2f}] {r.rule_id}  {loc}")
        print(f"      {r.reason}")
    if not (down or fp):
        print("  (no downgrade candidates — all examined findings look real)")
