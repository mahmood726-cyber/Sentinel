"""P2-hallucination-classifier: WARN when a small classifier model judges
that a rendered body claim is unsupported by its context.

E156 Assurance Standard "Made-up citations" + "Overclaiming" coverage extension.
Where the deterministic Phase-1 rules (citation_cascade, claim_language,
denominator_logic) catch structural defects, this rule catches semantic
unsupportedness — the classifier is asked: given the surrounding context
(the workbook DATA line + references), is this body sentence plausibly
derivable from the cited evidence?

Phase 3 status: SCAFFOLD. The rule is registered, manifest is clean,
zero firings on live e156 in default mode. It activates when:

  - HF_API_KEY env var is set: routes each body to HuggingFace Inference
    API for PatronusAI/Lynx-8B (preferred) or vectara/hallucination_evaluation_model.
  - HALLUCINATION_LOCAL=1 + transformers + torch installed: future
    local-inference path (Phase 4; not implemented in this commit).

Without any of the above: returns no findings (degrades silently).

This avoids forcing an 8 GB model download on every operator while keeping
the integration point clean for Phase 4.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sentinel.core import RepoContext, Severity, Verdict


ID = "P2-hallucination-classifier"
SEVERITY = Severity.WARN
SOURCE = ("F:\\e156\\docs\\assurance-standard.md  "
          "(Lynx-8B / HHEM-2.1-Open hallucination tier — Phase 3 scaffold; "
          "Phase 4 wires local model)")
SCOPE = "repo"

MAX_FILE_BYTES = 10_000_000
HF_API_KEY = os.environ.get("HF_API_KEY", "").strip()
HF_MODEL = os.environ.get(
    "HALLUCINATION_MODEL",
    "vectara/hallucination_evaluation_model",
)
HALLUCINATION_THRESHOLD = float(os.environ.get("HALLUCINATION_THRESHOLD", "0.7"))

CURRENT_BODY_RE = re.compile(
    r"^CURRENT BODY[^\n]*\n(.*?)(?=\n\nYOUR REWRITE|\n\nSUBMISSION|\n=)",
    re.MULTILINE | re.DOTALL,
)
ENTRY_HEAD_RE = re.compile(r"^\[(\d+)/\d+\]\s+(.+?)\s*$", re.MULTILINE)
DATA_LINE_RE = re.compile(r"^DATA:\s+(.+?)\s*$", re.MULTILINE)
SEP = "=" * 70


def _classify_via_api(body: str, context: str) -> tuple[float, str] | None:
    """Call HF Inference API. Returns (hallucination_score, raw_response_excerpt)
    or None if the call can't be made or fails. The rule degrades silently
    on any error — operator must explicitly check the API key / quota."""
    if not HF_API_KEY:
        return None
    url = f"https://api-inference.huggingface.co/models/{HF_MODEL}"
    # Both Lynx and HHEM accept (premise, hypothesis) shaped pairs.
    payload = json.dumps({
        "inputs": {"premise": context, "hypothesis": body},
        "options": {"wait_for_model": True, "use_cache": True},
    }).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {HF_API_KEY}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
        return None

    # Heuristic score extraction. The HHEM-2.1 endpoint returns
    # [{"label":"hallucination","score":0.XX}, ...]; Lynx returns
    # {"label": "...", "score": ...}. Handle both shapes.
    score = None
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and "hallucination" in str(item.get("label", "")).lower():
                try:
                    score = float(item.get("score", 0))
                except (TypeError, ValueError):
                    pass
    elif isinstance(data, dict):
        try:
            score = float(data.get("score", 0))
        except (TypeError, ValueError):
            pass
    if score is None:
        return None
    return score, str(data)[:200]


def _iter_target_files(root: Path):
    """Same target set as claim_language — rendered + source body text only."""
    wb = root / "rewrite-workbook.txt"
    if wb.is_file():
        yield wb


def _check_one_file(text: str, rel: str, now: datetime) -> List[Verdict]:
    verdicts: List[Verdict] = []
    # API call is rate-limited — do not scan the workbook entry by entry
    # if no API key is set. In scaffold mode (no key), return immediately.
    if not HF_API_KEY:
        return verdicts

    # Per-entry classification: only scan entries with a CURRENT BODY block
    for blk in text.split(SEP):
        hm = ENTRY_HEAD_RE.search(blk)
        if not hm:
            continue
        body_m = CURRENT_BODY_RE.search(blk)
        if not body_m:
            continue
        body = body_m.group(1).strip()
        data_m = DATA_LINE_RE.search(blk)
        context = data_m.group(1).strip() if data_m else ""
        if not body or len(body) < 50:
            continue
        result = _classify_via_api(body, context or "(no context)")
        if result is None:
            continue
        score, raw = result
        if score >= HALLUCINATION_THRESHOLD:
            verdicts.append(Verdict(
                rule_id=ID,
                severity=Severity.WARN,
                repo=None,
                file=rel,
                line=text.count("\n", 0, hm.start()) + 1,
                detail=(
                    f"entry #{hm.group(1)} body classified as likely "
                    f"hallucinated (score {score:.2f} >= "
                    f"{HALLUCINATION_THRESHOLD}) by {HF_MODEL}"
                ),
                fix_hint=(
                    "re-read the cited DATA line and verify the body's "
                    "claims are derivable from it; or supply the missing "
                    "premise context in the entry's metadata"
                ),
                source=SOURCE,
                timestamp=now,
            ))
    return verdicts


def check(ctx: RepoContext) -> List[Verdict]:
    now = datetime.now(timezone.utc)
    verdicts: List[Verdict] = []
    root = ctx.repo_root
    for path in _iter_target_files(root):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(root).as_posix()
        for v in _check_one_file(text, rel, now):
            verdicts.append(Verdict(
                rule_id=v.rule_id,
                severity=v.severity,
                repo=str(root),
                file=v.file,
                line=v.line,
                detail=v.detail,
                fix_hint=v.fix_hint,
                source=v.source,
                timestamp=v.timestamp,
            ))
    return verdicts
