"""Convert Sentinel verdicts to SARIF 2.1.0 for GitHub code-scanning.

Why SARIF (and not just JSONL):
  GitHub's "Security" tab and the in-PR annotations consume SARIF natively.
  GitLab SAST, Azure DevOps, Sonatype, Snyk, and most IDEs also do.
  Emitting SARIF lets Sentinel findings appear in those UIs without a
  custom integration per consumer.

Mapping decisions:
  - Severity → SARIF level: BLOCK→error, WARN→warning, INFO→note.
    SARIF also has 'none' but it's reserved for "informational, do not
    surface as a finding" so we use 'note' for INFO.
  - rule_id → ruleId on the result, AND a rule definition in
    tool.driver.rules. Spec §3.27.5 requires the latter so consumers
    can show the rule's full description.
  - file/line → physicalLocation.artifactLocation.uri / region.startLine.
    Repo-wide findings (no file) omit the locations array entirely;
    SARIF spec §3.27.12 allows this.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""
from __future__ import annotations
from typing import Sequence

from sentinel.core import Severity, Verdict

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
SENTINEL_INFO_URI = "https://github.com/mahmood726-cyber/Sentinel"

# Set lazily from pyproject.toml at import time so users get an accurate
# version in their CI logs without us hardcoding a stale value.
def _sentinel_version() -> str:
    try:
        from importlib.metadata import version
        return version("sentinel")
    except Exception:  # noqa: BLE001 — best-effort; never fail a scan over version lookup
        return "unknown"


_SEVERITY_TO_LEVEL = {
    Severity.BLOCK: "error",
    Severity.WARN: "warning",
    Severity.INFO: "note",
}


def _verdict_to_result(v: Verdict) -> dict:
    result: dict = {
        "ruleId": v.rule_id,
        "level": _SEVERITY_TO_LEVEL[v.severity],
        "message": {"text": v.detail or v.rule_id},
    }
    if v.file:
        physical_location: dict = {
            "artifactLocation": {"uri": v.file.replace("\\", "/")},
        }
        if v.line is not None:
            physical_location["region"] = {"startLine": int(v.line)}
        result["locations"] = [{"physicalLocation": physical_location}]
    return result


def _rule_definition(rule_id: str, sample_verdict: Verdict) -> dict:
    """Build a tool.driver.rules entry from one verdict that uses the rule.
    SARIF requires id + name; we also include shortDescription from the
    verdict's source field so consumers show useful copy."""
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {
            "text": sample_verdict.source[:120] if sample_verdict.source else rule_id,
        },
        "helpUri": SENTINEL_INFO_URI,
    }


def verdicts_to_sarif(verdicts: Sequence[Verdict]) -> dict:
    """Build a SARIF 2.1.0 dict from a list of Sentinel verdicts.

    Returns a dict that round-trips through json.dumps without further
    transformation. Empty input produces a valid empty SARIF.
    """
    # Stable rule definitions: one entry per unique rule_id, using the
    # first verdict per rule as the descriptor source.
    seen_rules: dict[str, Verdict] = {}
    for v in verdicts:
        seen_rules.setdefault(v.rule_id, v)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sentinel",
                        "version": _sentinel_version(),
                        "informationUri": SENTINEL_INFO_URI,
                        "rules": [
                            _rule_definition(rid, v) for rid, v in seen_rules.items()
                        ],
                    },
                },
                "results": [_verdict_to_result(v) for v in verdicts],
            }
        ],
    }
