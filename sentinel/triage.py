"""LLM-triage precision layer for Sentinel verdicts.

Sentinel's pattern rules are the *recall* layer — cheap, deterministic, and
intentionally over-fire rather than miss (see memory `sentinel-fp-audit`). This
module is the optional *precision* layer: an LLM re-reads each verdict with
surrounding code context and judges whether it is feasible in context, so noisy
BLOCKs can be downgraded to WARN for review.

Design constraints (non-negotiable):
- **Never in the blocking hook path.** This runs only via `sentinel triage`, on
  verdicts that have already been produced. The pre-push gate stays fast and
  deterministic.
- **Fail-closed.** Any error, missing file, unparseable model output, or absent
  backend yields verdict ``keep`` — a real finding is never silently dropped.
- **Downgrade-only, never delete.** Applying triage can demote BLOCK -> WARN; it
  never removes a verdict and never touches WARN/INFO severities.
- **Advisory, not authoritative (P2-10).** A demotion is a suggestion: the new
  verdict carries ADVISORY_MARKER in its `source` so the Overmind aggregator can
  tell it from a deterministic WARN, and the CLI refuses to write triage output
  over the canonical finding logs Overmind reads. An LLM never silently weakens
  the gate.
- **Optional dependency.** Sentinel core stays dependency-free. Triage no-ops if
  no backend is configured (no ANTHROPIC_API_KEY and no local ollama).

The model call is injected (`llm_call`) so tests run fully offline.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, List, Optional, Tuple

from sentinel.core import RepoContext, ScanMode, Severity, Verdict

# A callable that takes a prompt string and returns the model's text response.
LLMCall = Callable[[str], str]

VALID_VERDICTS = ("keep", "downgrade", "likely_fp")

# Stable provenance marker stamped into the `source` of any verdict an LLM
# triage pass demotes. Consumers (Overmind aggregation, dashboards) MUST treat a
# verdict carrying this marker as advisory — it must never count as a
# deterministic gate result. Kept as a module constant so both Sentinel and
# downstream tooling reference one literal.
ADVISORY_MARKER = "[llm-triage-advisory]"


@dataclass
class TriageResult:
    rule_id: str
    file: Optional[str]
    line: Optional[int]
    original_severity: str
    verdict: str          # one of VALID_VERDICTS
    confidence: float     # 0.0 .. 1.0
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Loading verdicts from a saved scan JSON / scanning fresh
# --------------------------------------------------------------------------- #
def _verdict_from_dict(d: dict) -> Verdict:
    try:
        ts = datetime.fromisoformat(d["timestamp"])
    except (KeyError, ValueError, TypeError):
        ts = datetime(1970, 1, 1)
    return Verdict(
        rule_id=d.get("rule_id", "?"),
        severity=Severity.from_string(d.get("severity", "WARN")),
        repo=d.get("repo", ""),
        file=d.get("file"),
        line=d.get("line"),
        detail=d.get("detail", ""),
        fix_hint=d.get("fix_hint", ""),
        source=d.get("source", ""),
        timestamp=ts,
    )


def load_verdicts_json(path: Path) -> List[Verdict]:
    """Load verdicts from a `sentinel scan --json` file ({"verdicts": [...]}) or
    a bare list of verdict dicts."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    raw = data.get("verdicts", data) if isinstance(data, dict) else data
    return [_verdict_from_dict(d) for d in raw]


def scan_repo(repo: Path) -> List[Verdict]:
    """Run all rules against a repo, returning verdicts (mirrors `scan` core)."""
    from sentinel.registry.registry import Registry
    rules_root = Path(__file__).parent / "rules"
    ctx = RepoContext(repo_root=repo, mode=ScanMode.REPO)
    reg = Registry.from_dir(rules_root)
    verdicts: List[Verdict] = []
    for rule in reg.all_rules():
        verdicts.extend(rule.check(ctx))
    return verdicts


# --------------------------------------------------------------------------- #
# Context extraction
# --------------------------------------------------------------------------- #
def _read_context(v: Verdict, repo_root: Optional[Path], context_lines: int) -> Optional[str]:
    """Return a numbered code window around the verdict, target line marked, or None."""
    if not v.file:
        return None
    p = Path(v.file)
    base = repo_root or (Path(v.repo) if v.repo else None)
    if base and not p.is_absolute():
        p = base / v.file
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if not lines:
        return None
    ln = v.line or 1
    lo = max(1, ln - context_lines)
    hi = min(len(lines), ln + context_lines)
    out = []
    for i in range(lo, hi + 1):
        marker = ">>" if i == ln else "  "
        out.append(f"{marker}{i:>5}| {lines[i - 1]}")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Prompt
# --------------------------------------------------------------------------- #
PROMPT_TEMPLATE = """You are a precise static-analysis triage assistant. A pattern-based linter \
(Sentinel) flagged the code below. Pattern rules over-fire by design, so your job is to decide \
whether THIS finding is a real issue in context or a false positive.

Rule: {rule_id} (severity {severity})
Detail: {detail}
{fix_hint}Code (target line marked with >>):
---
{context}
---

Decide one verdict:
- "keep": the finding is plausibly a real issue here.
- "downgrade": probably not a real issue, but not certain enough to dismiss.
- "likely_fp": clearly a false positive in this context (e.g. an upstream guard \
exists, it is documentation/test/vendored code, the matched token is unrelated).

Be conservative: if you are unsure, choose "keep". Do NOT invent context you cannot see.

Respond with ONLY a JSON object, no prose:
{{"verdict": "keep|downgrade|likely_fp", "confidence": 0.0-1.0, "reason": "<=20 words"}}"""


def _build_prompt(v: Verdict, context: str) -> str:
    fh = f"Fix hint: {v.fix_hint}\n" if v.fix_hint else ""
    return PROMPT_TEMPLATE.format(
        rule_id=v.rule_id, severity=v.severity.label,
        detail=v.detail, fix_hint=fh, context=context,
    )


def _parse_response(text: str) -> Tuple[str, float, str]:
    """Tolerantly parse the model's JSON. Fail-closed to ('keep', 0.0, ...)."""
    if not text:
        return "keep", 0.0, "empty model response"
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return "keep", 0.0, "no JSON in model response"
    try:
        obj = json.loads(m.group(0))
    except (json.JSONDecodeError, ValueError):
        return "keep", 0.0, "unparseable model JSON"
    verdict = str(obj.get("verdict", "keep")).strip().lower()
    if verdict not in VALID_VERDICTS:
        verdict = "keep"
    try:
        conf = float(obj.get("confidence", 0.0))
    except (TypeError, ValueError):
        conf = 0.0
    conf = max(0.0, min(1.0, conf))
    reason = str(obj.get("reason", "")).strip()[:200]
    return verdict, conf, reason


# --------------------------------------------------------------------------- #
# Core
# --------------------------------------------------------------------------- #
def triage_verdicts(
    verdicts: List[Verdict],
    llm_call: LLMCall,
    *,
    repo_root: Optional[Path] = None,
    context_lines: int = 30,
    only_blocks: bool = True,
) -> List[TriageResult]:
    """Triage verdicts. By default only BLOCK verdicts (the ones that gate a push)."""
    results: List[TriageResult] = []
    for v in verdicts:
        if only_blocks and v.severity != Severity.BLOCK:
            continue
        ctx = _read_context(v, repo_root, context_lines)
        if ctx is None:
            results.append(TriageResult(
                v.rule_id, v.file, v.line, v.severity.label,
                "keep", 0.0, "could not read file context"))
            continue
        try:
            resp = llm_call(_build_prompt(v, ctx))
            verdict, conf, reason = _parse_response(resp)
        except Exception as e:  # noqa: BLE001 - fail-closed on ANY backend error
            verdict, conf, reason = "keep", 0.0, f"triage error: {type(e).__name__}"
        results.append(TriageResult(
            v.rule_id, v.file, v.line, v.severity.label, verdict, conf, reason))
    return results


def apply_triage(
    verdicts: List[Verdict],
    results: List[TriageResult],
    *,
    min_confidence: float = 0.8,
) -> List[Verdict]:
    """Return a NEW verdict list with confidently-FP BLOCKs demoted to WARN.

    Downgrade-only: BLOCK -> WARN. Never removes a verdict; never touches
    WARN/INFO. A verdict is demoted only when a matching triage result says
    'downgrade'/'likely_fp' with confidence >= min_confidence.
    """
    demote = {
        (r.rule_id, r.file, r.line)
        for r in results
        if r.verdict in ("downgrade", "likely_fp") and r.confidence >= min_confidence
    }
    out: List[Verdict] = []
    for v in verdicts:
        if v.severity == Severity.BLOCK and (v.rule_id, v.file, v.line) in demote:
            # Advisory-only (P2-10): an LLM downgrade is a *suggestion*, not a
            # deterministic verdict. Stamp a stable, machine-detectable marker
            # (ADVISORY_MARKER) into source so any consumer — especially the
            # Overmind aggregator — can tell an LLM-triaged WARN from a real
            # deterministic WARN and refuse to let it silently weaken the gate.
            out.append(Verdict(
                rule_id=v.rule_id, severity=Severity.WARN, repo=v.repo,
                file=v.file, line=v.line,
                detail=f"{v.detail}  [triage: downgraded from BLOCK — advisory]",
                fix_hint=v.fix_hint,
                source=f"{v.source} {ADVISORY_MARKER}",
                timestamp=v.timestamp))
        else:
            out.append(v)
    return out


# --------------------------------------------------------------------------- #
# Backends (auto-detect: Anthropic API -> local ollama -> None)
# --------------------------------------------------------------------------- #
_ANTHROPIC_MODEL = os.environ.get("SENTINEL_TRIAGE_ANTHROPIC_MODEL", "claude-haiku-4-5")
_OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
_OLLAMA_MODEL = os.environ.get("SENTINEL_TRIAGE_OLLAMA_MODEL", "qwen2.5-coder")


def _anthropic_backend() -> Optional[LLMCall]:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    try:
        import anthropic  # type: ignore
    except ImportError:
        return None
    client = anthropic.Anthropic()

    def call(prompt: str) -> str:
        msg = client.messages.create(
            model=_ANTHROPIC_MODEL, max_tokens=256,
            messages=[{"role": "user", "content": prompt}])
        return "".join(getattr(b, "text", "") for b in msg.content)

    return call


def _ollama_reachable() -> bool:
    try:
        with urllib.request.urlopen(f"{_OLLAMA_HOST}/api/tags", timeout=1.5) as r:
            return r.status == 200
    except Exception:  # noqa: BLE001
        return False


def _ollama_backend() -> Optional[LLMCall]:
    if not _ollama_reachable():
        return None

    def call(prompt: str) -> str:
        payload = json.dumps({
            "model": _OLLAMA_MODEL, "prompt": prompt, "stream": False,
            "options": {"temperature": 0}}).encode()
        req = urllib.request.Request(
            f"{_OLLAMA_HOST}/api/generate", data=payload,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode()).get("response", "")

    return call


def detect_backend() -> Tuple[Optional[str], Optional[LLMCall]]:
    """Auto-detect: Anthropic API if key set, else local ollama, else (None, None)."""
    call = _anthropic_backend()
    if call:
        return f"anthropic:{_ANTHROPIC_MODEL}", call
    call = _ollama_backend()
    if call:
        return f"ollama:{_OLLAMA_MODEL}", call
    return None, None
