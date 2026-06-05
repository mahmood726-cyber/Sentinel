# sentinel:skip-file — fixtures contain example effect-claim strings without DOIs.
"""Tests for P1-claim-grounding: WARN on quantitative claims with no source locator."""
from __future__ import annotations

from pathlib import Path

from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.plugin_loader import load_plugin_rule

PLUGIN_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "plugins" / "claim_grounding.py"
)


def _rule():
    return load_plugin_rule(PLUGIN_PATH)


def _ctx(tmp_path: Path) -> RepoContext:
    return RepoContext(repo_root=tmp_path, mode=ScanMode.REPO)


def _warns(verdicts):
    return [v for v in verdicts if v.severity == Severity.WARN and v.rule_id == "P1-claim-grounding"]


def test_ungrounded_claim_warns(tmp_path):
    (tmp_path / "capsule.md").write_text(
        "# Result\n\nThe intervention reduced events (HR 0.74, 95% CI 0.65 to 0.85; p < 0.001).\n",
        encoding="utf-8",
    )
    assert len(_warns(_rule().check(_ctx(tmp_path)))) == 1


def test_claim_with_doi_is_cleared(tmp_path):
    (tmp_path / "capsule.md").write_text(
        "# Result\n\nThe intervention reduced events (HR 0.74, 95% CI 0.65 to 0.85).\n"
        "Source: doi:10.1056/NEJMoa1911303\n",
        encoding="utf-8",
    )
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_claim_with_nct_is_cleared(tmp_path):
    (tmp_path / "capsule.md").write_text(
        "RR 0.70 reported in NCT03036124.\n", encoding="utf-8"
    )
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_no_quantitative_claim_is_inert(tmp_path):
    (tmp_path / "notes.md").write_text(
        "# Plan\n\nWe will design a randomized trial and write a protocol.\n",
        encoding="utf-8",
    )
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_skip_marker_suppresses(tmp_path):
    (tmp_path / "fixture.md").write_text(
        "sentinel:skip-file\nHR 0.74 (95% CI 0.65 to 0.85)\n", encoding="utf-8"
    )
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_percent_reduction_claim_warns(tmp_path):
    (tmp_path / "c.md").write_text(
        "Treatment lowered hospitalization by 30% versus placebo.\n", encoding="utf-8"
    )
    assert len(_warns(_rule().check(_ctx(tmp_path)))) == 1


def test_english_or_followed_by_number_is_not_a_claim(tmp_path):
    """Regression (2026-06-03): lowercase 'or 3' (English conjunction) must NOT match
    the odds-ratio pattern. Found as a false positive on overmind design docs."""
    (tmp_path / "doc.md").write_text(
        "Choose option 2 or 3 depending on the runner. We support rr or hr modes.\n",
        encoding="utf-8",
    )
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_bare_ratio_phrase_without_number_is_not_a_claim(tmp_path):
    """Regression (2026-06-05): a spelled-out 'hazard/risk/odds ratio' with NO adjacent
    number is a methodological mention or an illustrative example, not a quantitative
    claim. Found as a false positive on overmind's memory-and-dreaming design doc, whose
    table cell read '...hazard ratio edge case failed'."""
    (tmp_path / "design.md").write_text(
        "| Verification failed | regression | \"prognostic-meta: hazard ratio edge case failed\" |\n"
        "We compute an odds ratio internally and may report the risk ratio later.\n",
        encoding="utf-8",
    )
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_spelled_out_ratio_with_number_still_warns(tmp_path):
    """Counterpart: the spelled-out phrase WITH a value next to it is a real ungrounded
    claim and must still warn (kept recall while killing the bare-phrase FP)."""
    (tmp_path / "a.md").write_text("The hazard ratio of 0.74 favored treatment.\n", encoding="utf-8")
    assert len(_warns(_rule().check(_ctx(tmp_path)))) == 1
    (tmp_path / "b.md").write_text("A 0.74 hazard ratio favored treatment.\n", encoding="utf-8")
    # two separate claim-bearing files -> two warns
    assert len(_warns(_rule().check(_ctx(tmp_path)))) == 2


def test_uppercase_ratio_estimate_still_warns(tmp_path):
    (tmp_path / "doc.md").write_text("The adjusted OR 1.45 indicated higher risk.\n", encoding="utf-8")
    assert len(_warns(_rule().check(_ctx(tmp_path)))) == 1


def test_explicit_equals_ratio_warns(tmp_path):
    (tmp_path / "doc.md").write_text("Effect was HR = 2 in the subgroup.\n", encoding="utf-8")
    assert len(_warns(_rule().check(_ctx(tmp_path)))) == 1


def test_tool_output_artifacts_are_excluded(tmp_path):
    """Sentinel/Overmind generated logs quote prior findings (which may contain
    'hazard ratio') and must not self-trip this rule. (Observed 2026-06-03.)"""
    (tmp_path / "sentinel-findings.md").write_text(
        "[WARN] document states a hazard ratio but carries no locator\n", encoding="utf-8")
    (tmp_path / "STUCK_FAILURES.md").write_text("a 30% reduction was claimed\n", encoding="utf-8")
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_workflow_state_dir_is_excluded(tmp_path):
    """Generated agent working-state artifacts (e.g. .workflow-state/findings_diff.md
    held 160 quoted 'claims' in the 2026-06-03 sweep) must not trip the rule."""
    wf = tmp_path / ".workflow-state"
    wf.mkdir()
    (wf / "findings_diff.md").write_text("HR 0.74 (95% CI 0.65 to 0.85) appeared in a finding\n", encoding="utf-8")
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_archive_and_snapshot_dirs_are_excluded(tmp_path):
    """Frozen historical copies (archive/, release-snapshots/) are not the live
    authored capsule — re-auditing their grounding is noise (~70 such hits in one
    app's archive/ in the 2026-06-04 allmeta sweep)."""
    for sub in ("archive", "release-snapshots"):
        d = tmp_path / "app" / sub
        d.mkdir(parents=True)
        (d / "old.md").write_text("HR 0.74 (95% CI 0.65 to 0.85); p < 0.001\n", encoding="utf-8")
    assert _warns(_rule().check(_ctx(tmp_path))) == []
    # ...but the live copy at the app root still warns.
    (tmp_path / "app" / "index.md").write_text("HR 0.74 (95% CI 0.65 to 0.85)\n", encoding="utf-8")
    assert len(_warns(_rule().check(_ctx(tmp_path)))) == 1


def test_backup_prefixed_dir_is_excluded(tmp_path):
    """backup_<date> dirs carry a varying suffix, so they're caught by prefix, not
    exact name. A frozen backup copy must not trip the rule."""
    d = tmp_path / "app" / "backup_2026_01_13"
    d.mkdir(parents=True)
    (d / "index.html").write_text("<p>HR 0.74 (95% CI 0.65 to 0.85)</p>\n", encoding="utf-8")
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_claim_inside_script_block_is_not_a_claim(tmp_path):
    """JS source inside <script> (e.g. `p < 0.5`, `RR: 1`) is code, not an empirical
    claim. A static HTML doc whose only 'claims' live in a script must not warn."""
    (tmp_path / "doc.html").write_text(
        "<html><body><h1>Notes</h1>\n"
        "<script>var q = p < 0.5 ? p : 1 - p; const K = { RR: 1, OR: 1 };</script>\n"
        "</body></html>\n",
        encoding="utf-8",
    )
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_interactive_calculator_html_is_exempt(tmp_path):
    """An interactive tool (textarea paste-in, or 2+ form controls) is a calculator,
    not a claim-bearing document — its '95% CI' header / 'odds ratio' method prose
    is UI chrome, not an empirical finding."""
    (tmp_path / "index.html").write_text(
        "<html><body>\n"
        "<textarea id='data'></textarea><button>Compute</button>\n"
        "<table><thead><tr><th>Effect</th><th>95% CI</th></tr></thead></table>\n"
        "<p>Uses the Peto one-step odds ratio for rare events.</p>\n"
        "</body></html>\n",
        encoding="utf-8",
    )
    assert _warns(_rule().check(_ctx(tmp_path))) == []
    # Two inputs (no textarea) also qualifies as a tool.
    (tmp_path / "calc.html").write_text(
        "<input id='a'><input id='b'>\n<th>95% CI</th>\n", encoding="utf-8")
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_bare_url_does_not_clear_the_doc(tmp_path):
    """A2 (2026-06-04): a generic URL (logo/CDN src, footer link) is NOT a resolvable
    citation. A capsule asserting an effect with only a boilerplate URL must still
    warn — the bare https?:// catch-all that cleared any-doc-with-any-URL is gone."""
    (tmp_path / "capsule.html").write_text(
        "<html><body><p>The intervention reduced mortality (HR 0.74, 95% CI 0.65 to 0.85).</p>\n"
        "<img src='https://cdn.example.com/logo.png'>\n"
        "<a href='http://localhost:8080/preview'>local</a>\n"
        "</body></html>\n",
        encoding="utf-8",
    )
    assert len(_warns(_rule().check(_ctx(tmp_path)))) == 1


def test_source_shaped_urls_still_clear(tmp_path):
    """A real PubMed / DOI-resolver / CT.gov URL is a resolvable locator and clears."""
    for locator in (
        "https://pubmed.ncbi.nlm.nih.gov/31535829/",
        "https://doi.org/10.1056/NEJMoa1911303",
        "https://clinicaltrials.gov/study/NCT03036124",
    ):
        d = tmp_path / locator.split("//")[1].split("/")[0]
        d.mkdir(exist_ok=True)
        (d / "c.md").write_text(f"HR 0.74 (95% CI 0.65 to 0.85). See {locator}\n", encoding="utf-8")
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_short_pmc_token_does_not_clear_but_real_pmcid_does(tmp_path):
    """C (2026-06-04): 'PMC1'/'PMC9' (committee numbers, path fragments) are not
    PMCIDs — only 5-8 digit PMC\\d clears. A doc cleared only by 'PMC1' must warn."""
    (tmp_path / "fp.md").write_text(
        "The PMC1 committee met. HR 0.74 (95% CI 0.65 to 0.85) was reported.\n", encoding="utf-8")
    assert len(_warns(_rule().check(_ctx(tmp_path)))) == 1
    (tmp_path / "ok.md").write_text(
        "HR 0.74 (95% CI 0.65 to 0.85); full text PMC7654321.\n", encoding="utf-8")
    # the real PMCID file clears; only fp.md remains -> still exactly one warn
    assert len(_warns(_rule().check(_ctx(tmp_path)))) == 1


def test_version_string_does_not_clear_as_bare_doi(tmp_path):
    """C: a free-floating dotted-number/slash token ('10.1234/version2') is a software
    version, not a DOI, and must not clear a claim-bearing doc."""
    (tmp_path / "v.md").write_text(
        "Upgraded to 10.1234/version2 build. HR 0.74 (95% CI 0.65 to 0.85).\n", encoding="utf-8")
    assert len(_warns(_rule().check(_ctx(tmp_path)))) == 1


def test_english_or_between_numbers_is_not_a_claim(tmp_path):
    """C: uppercase 'OR' as the English conjunction between two figures
    ('5 OR 3.5 ways') is not an odds-ratio estimate."""
    (tmp_path / "doc.md").write_text("There were 5 OR 3.5 ways to route the call.\n", encoding="utf-8")
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_95pct_ci_prose_without_value_is_not_a_claim(tmp_path):
    """C: a bare '95 % CI' not followed by an interval value ('chapter 95 % CI of the
    room', or CI = continuous integration) is not an effect estimate."""
    (tmp_path / "doc.md").write_text("See chapter 95 % CI of the room for the CI pipeline.\n", encoding="utf-8")
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_generated_report_names_are_excluded(tmp_path):
    """C: generated machine-written reports (progress.md, *findings*.md, *nightly*.md)
    quote prior claim text and must not self-trip — parametrised name shapes, not a
    hardcoded 2-name list."""
    for name in ("progress.md", "review_findings_x.md", "overmind_nightly_2026.md", "aggregate-findings.md"):
        (tmp_path / name).write_text("HR 0.74 (95% CI 0.65 to 0.85); a 30% reduction.\n", encoding="utf-8")
    assert _warns(_rule().check(_ctx(tmp_path))) == []


def test_static_html_manuscript_still_warns(tmp_path):
    """Guard against over-exemption: a static HTML doc with NO form controls and a
    real ungrounded claim must still warn (it's a manuscript export, not a tool)."""
    (tmp_path / "paper.html").write_text(
        "<html><body><h1>Results</h1>\n"
        "<p>The intervention reduced mortality (HR 0.74, 95% CI 0.65 to 0.85).</p>\n"
        "</body></html>\n",
        encoding="utf-8",
    )
    assert len(_warns(_rule().check(_ctx(tmp_path)))) == 1
