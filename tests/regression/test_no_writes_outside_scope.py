"""Non-regression: Sentinel writes only to `tmp_repo` under test + nothing
under the Sentinel package source tree itself."""
from pathlib import Path
import pytest

from sentinel.core import RepoContext, ScanMode
from sentinel.io import write_findings
from sentinel.registry.registry import Registry

SENTINEL_PKG = Path(__file__).parent.parent.parent / "sentinel"
RULES_ROOT = SENTINEL_PKG / "rules"


def _snapshot(root: Path) -> dict[Path, float]:
    return {p: p.stat().st_mtime_ns for p in root.rglob("*") if p.is_file()}


@pytest.mark.regression
def test_full_scan_does_not_touch_sentinel_source_tree(tmp_path: Path):
    bad = tmp_path / "scan_target"
    bad.mkdir()
    (bad / "cert.json").write_text(
        '{"sig":"SIG_RSA_SHA256_x"}', encoding="utf-8"
    )

    before = _snapshot(SENTINEL_PKG)
    reg = Registry.from_dir(RULES_ROOT)
    ctx = RepoContext(repo_root=bad, mode=ScanMode.REPO)
    verdicts = []
    for rule in reg.all_rules():
        verdicts.extend(rule.check(ctx))
    write_findings(bad, verdicts)
    after = _snapshot(SENTINEL_PKG)

    assert before == after, (
        "Sentinel package source tree was modified during scan; "
        "writes must only target the scanned repo."
    )
    assert (bad / "STUCK_FAILURES.md").exists(), "BLOCK verdicts must land in target repo"
