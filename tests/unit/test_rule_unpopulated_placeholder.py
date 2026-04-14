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

def test_unpopulated_placeholder_ignores_css_fstring_escapes(tmp_path: Path):
    """CSS braces inside an f-string template ({{background:#fff}}) are
    NOT unpopulated placeholders — they're f-string-escaped literal braces
    that render as single `{` / `}`. The rule must only fire on
    identifier-like Jinja/Mustache placeholders."""
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
