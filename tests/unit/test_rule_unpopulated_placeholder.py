from pathlib import Path
from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.yaml_loader import load_yaml_rule


RULE_PATH = (
    Path(__file__).parent.parent.parent
    / "sentinel" / "rules" / "yaml" / "P1-unpopulated-placeholder.yaml"
)


def test_unpopulated_placeholder_fires_on_bad_fixture(fixtures_dir: Path):
    rule = load_yaml_rule(RULE_PATH)
    bad = fixtures_dir / "repos" / "placeholder_BAD"
    verdicts = rule.check(RepoContext(repo_root=bad, mode=ScanMode.REPO))
    assert len(verdicts) >= 1
    assert all(v.severity == Severity.WARN for v in verdicts)


def test_unpopulated_placeholder_silent_on_good_fixture(fixtures_dir: Path):
    rule = load_yaml_rule(RULE_PATH)
    good = fixtures_dir / "repos" / "placeholder_GOOD"
    verdicts = rule.check(RepoContext(repo_root=good, mode=ScanMode.REPO))
    assert verdicts == []


# Refinement tests: don't fire on CSS-in-f-string or nested test fixtures.

def test_unpopulated_placeholder_ignores_non_identifier_braces(tmp_path: Path):
    """Text-level regression: CSS-like `{{background:#fff}}` inside any file
    (f-string, template literal, raw text) must NOT fire. The rule greps
    text; the f-string surrounding it is irrelevant — what matters is that
    after an identifier the next char is a Jinja discriminator (`|`, `[`,
    `.ident`, `-?}}`) and not CSS punctuation (`:`)."""
    (tmp_path / "dashboard.py").write_text(
        'html = f".WARN{{background:#fff4d6;color:#6b4a00}}"\n'
        'css = f"table{{width:100%;border-collapse:collapse}}"\n',
        encoding="utf-8",
    )
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert verdicts == [], f"got false-positives: {[v.detail for v in verdicts]}"


def test_unpopulated_placeholder_still_fires_on_jinja(tmp_path: Path):
    """Real Jinja/Mustache placeholders like {{user_name}} must still block."""
    (tmp_path / "page.html").write_text(
        "<h1>Hello {{user_name}}</h1>\n<p>Path: {{ config.api_key }}</p>\n",
        encoding="utf-8",
    )
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert len(verdicts) == 2
    assert all(v.severity == Severity.WARN for v in verdicts)


def test_unpopulated_placeholder_fires_on_jinja_filter(tmp_path: Path):
    """Jinja filter syntax {{ x|filter }} — ad65952's tightened regex
    missed this. P0-1 (2026-04-15 review) requires coverage."""
    (tmp_path / "page.html").write_text(
        "<p>{{ name|upper }}</p>\n<p>{{ date|format_date('YYYY-MM-DD') }}</p>\n",
        encoding="utf-8",
    )
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert len(verdicts) == 2, f"both filter placeholders must fire, got {verdicts}"


def test_unpopulated_placeholder_fires_on_jinja_subscript(tmp_path: Path):
    """Jinja subscript {{ foo[0] }} — also missed by ad65952."""
    (tmp_path / "page.html").write_text(
        "<p>{{ items[0] }}</p>\n<p>{{ data['key'] }}</p>\n",
        encoding="utf-8",
    )
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert len(verdicts) == 2


def test_unpopulated_placeholder_fires_on_jinja_whitespace_control(tmp_path: Path):
    """Jinja whitespace-control {{- var -}} — ad65952's leading-identifier
    anchor rejected the leading `-`. P0-1 fix must accept it."""
    (tmp_path / "page.html").write_text(
        "<p>{{- user -}}</p>\n<p>{{-name-}}</p>\n",
        encoding="utf-8",
    )
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert len(verdicts) == 2


def test_unpopulated_placeholder_ignores_empty_braces(tmp_path: Path):
    """Empty {{}} or {{ }} is not a placeholder (no identifier inside)."""
    (tmp_path / "page.html").write_text(
        "<p>{{}}</p>\n<p>{{ }}</p>\n",
        encoding="utf-8",
    )
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert verdicts == []


def test_unpopulated_placeholder_still_ignores_css_colon(tmp_path: Path):
    """Regression guard: after the P0-1 widening, CSS-like {{property:value}}
    must still NOT match. The colon after the first token is the
    discriminator (CSS has `:`, Jinja has `|`, `[`, `.`, `}}`, or `-`)."""
    (tmp_path / "dashboard.py").write_text(
        'css = f"table{{width:100%;padding:0}}"\n'
        'hue = f".WARN{{background:#ffe0e0;color:#8a0000}}"\n',
        encoding="utf-8",
    )
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert verdicts == [], f"CSS false-positive regression: {[v.detail for v in verdicts]}"


def test_unpopulated_placeholder_literal_tokens_still_fire(tmp_path: Path):
    """Regression guard for the 4 non-Jinja alternatives in the P1 regex
    (REPLACE_ME, __PLACEHOLDER__, TBD:, XXX:). P1-10 required coverage."""
    (tmp_path / "notes.md").write_text(
        "Step 1: REPLACE_ME with real value.\n"
        "Note: __PLACEHOLDER__ here.\n"
        "TBD: finish this.\n"
        "XXX: hack until proper fix.\n",
        encoding="utf-8",
    )
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert len(verdicts) == 4
    matched = {v.detail for v in verdicts}
    for literal in ("REPLACE_ME", "__PLACEHOLDER__", "TBD:", "XXX:"):
        assert any(literal in d for d in matched), f"{literal} must fire"


def test_unpopulated_placeholder_excludes_nested_test_dirs(tmp_path: Path):
    """Workbench-style layout: <app>/tests/*.py containing FORBIDDEN tuples
    of literal template tokens is a test fixture, not shipping code."""
    app_tests = tmp_path / "forest-plot" / "tests"
    app_tests.mkdir(parents=True)
    (app_tests / "test_forest.py").write_text(
        'FORBIDDEN = ("{{", "}}", "REPLACE_ME", "__PLACEHOLDER__", "TBD:")\n',
        encoding="utf-8",
    )
    rule = load_yaml_rule(RULE_PATH)
    verdicts = rule.check(RepoContext(repo_root=tmp_path, mode=ScanMode.REPO))
    assert verdicts == [], f"nested test fixture should be excluded: {[v.file for v in verdicts]}"
