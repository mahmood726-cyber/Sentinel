from pathlib import Path
import pytest
from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.registry.yaml_loader import load_yaml_rule, YamlRuleLoadError


YAML_VALID = """
id: TEST-pattern-match
severity: BLOCK
scope: repo
description: Test rule
pattern: 'FORBIDDEN_TOKEN'
files: ['**/*.txt']
exclude: ['ignore/**']
fix_hint: Remove the token.
source: test.md#forbidden
"""


def test_load_yaml_rule_parses_all_fields(tmp_path: Path):
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(YAML_VALID, encoding="utf-8")
    rule = load_yaml_rule(rule_file)
    assert rule.id == "TEST-pattern-match"
    assert rule.severity == Severity.BLOCK
    assert rule.scope == "repo"
    assert rule.pattern == "FORBIDDEN_TOKEN"
    assert rule.files == ["**/*.txt"]
    assert rule.exclude == ["ignore/**"]


def test_load_yaml_rule_missing_required_field_raises(tmp_path: Path):
    rule_file = tmp_path / "bad.yaml"
    rule_file.write_text("id: incomplete\nseverity: BLOCK\n", encoding="utf-8")
    with pytest.raises(YamlRuleLoadError, match="missing required field"):
        load_yaml_rule(rule_file)


def test_load_yaml_rule_unknown_severity_raises(tmp_path: Path):
    rule_file = tmp_path / "bad.yaml"
    bad = YAML_VALID.replace("severity: BLOCK", "severity: CRITICAL")
    rule_file.write_text(bad, encoding="utf-8")
    with pytest.raises(YamlRuleLoadError, match="unknown severity"):
        load_yaml_rule(rule_file)


def test_yaml_rule_check_finds_pattern(tmp_path: Path):
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(YAML_VALID, encoding="utf-8")
    rule = load_yaml_rule(rule_file)

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "hit.txt").write_text("some FORBIDDEN_TOKEN here\n", encoding="utf-8")
    (repo / "miss.txt").write_text("clean content\n", encoding="utf-8")

    ctx = RepoContext(repo_root=repo, mode=ScanMode.REPO)
    verdicts = rule.check(ctx)
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "TEST-pattern-match"
    assert verdicts[0].file == "hit.txt"
    assert verdicts[0].line == 1


def test_yaml_rule_check_respects_exclude(tmp_path: Path):
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(YAML_VALID, encoding="utf-8")
    rule = load_yaml_rule(rule_file)

    repo = tmp_path / "repo"
    (repo / "ignore").mkdir(parents=True)
    (repo / "ignore" / "skip.txt").write_text("FORBIDDEN_TOKEN\n", encoding="utf-8")

    ctx = RepoContext(repo_root=repo, mode=ScanMode.REPO)
    assert rule.check(ctx) == []


def test_yaml_rule_scope_defaults_to_repo(tmp_path: Path):
    rule_file = tmp_path / "rule.yaml"
    no_scope = YAML_VALID.replace("scope: repo\n", "")
    rule_file.write_text(no_scope, encoding="utf-8")
    rule = load_yaml_rule(rule_file)
    assert rule.scope == "repo"


# Git enumeration safety controls (synthetic fixtures only).
# These regressions must fail against the pre-fix YAML scanner, which
# silently switches to filesystem traversal after an untrusted Git result.
def _yaml_git_test_repo(tmp_path: Path):
    from sentinel.core import RepoContext, ScanMode

    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(YAML_VALID, encoding="utf-8")
    repo = tmp_path / "git-repo"
    repo.mkdir()
    return load_yaml_rule(rule_file), repo, RepoContext(
        repo_root=repo, mode=ScanMode.REPO
    )


def test_yaml_git_listing_nonzero_is_internal_error_not_empty_or_rglob(tmp_path: Path, monkeypatch):
    import subprocess
    from sentinel.registry import yaml_loader
    from sentinel.io.git_files import GitFileEnumerationError

    rule, repo, ctx = _yaml_git_test_repo(tmp_path)
    (repo / ".git").mkdir()
    (repo / "hit.txt").write_text("FORBIDDEN_TOKEN\n", encoding="utf-8")
    monkeypatch.setattr(
        yaml_loader.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=["git"], returncode=128, stdout=b"", stderr=b"synthetic error"
        ),
    )
    with pytest.raises(GitFileEnumerationError, match="git ls-files"):
        rule.check(ctx)


def test_yaml_git_listing_timeout_is_internal_error_not_rglob(tmp_path: Path, monkeypatch):
    import subprocess
    from sentinel.registry import yaml_loader
    from sentinel.io.git_files import GitFileEnumerationError

    rule, repo, ctx = _yaml_git_test_repo(tmp_path)
    (repo / ".git").mkdir()
    (repo / "hit.txt").write_text("FORBIDDEN_TOKEN\n", encoding="utf-8")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="git ls-files", timeout=30)

    monkeypatch.setattr(yaml_loader.subprocess, "run", timeout)
    with pytest.raises(GitFileEnumerationError, match="git ls-files"):
        rule.check(ctx)


def test_yaml_linked_worktree_gitfile_uses_listing_not_unbounded_rglob(tmp_path: Path, monkeypatch):
    import subprocess
    from sentinel.registry import yaml_loader

    rule, repo, ctx = _yaml_git_test_repo(tmp_path)
    (repo / ".git").write_text("gitdir: synthetic-worktree-ref\n", encoding="utf-8")
    (repo / "clean.txt").write_text("valid content\n", encoding="utf-8")
    (repo / "ignored.txt").write_text("FORBIDDEN_TOKEN\n", encoding="utf-8")
    calls = []

    def successful_git(*args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(
            args=["git"], returncode=0, stdout=b"clean.txt\x00", stderr=b""
        )

    monkeypatch.setattr(yaml_loader.subprocess, "run", successful_git)
    assert rule.check(ctx) == []
    assert len(calls) == 1


def test_yaml_git_listing_valid_code_and_true_block_control(tmp_path: Path, monkeypatch):
    import subprocess
    from sentinel.registry import yaml_loader

    rule, repo, ctx = _yaml_git_test_repo(tmp_path)
    (repo / ".git").mkdir()
    (repo / "clean.txt").write_text("valid content\n", encoding="utf-8")
    (repo / "hit.txt").write_text("FORBIDDEN_TOKEN\n", encoding="utf-8")
    (repo / "ignored.txt").write_text("FORBIDDEN_TOKEN\n", encoding="utf-8")
    monkeypatch.setattr(
        yaml_loader.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=["git"], returncode=0,
            stdout=b"clean.txt\x00hit.txt\x00", stderr=b"",
        ),
    )
    findings = rule.check(ctx)
    assert [(v.file, v.line) for v in findings] == [("hit.txt", 1)]


@pytest.mark.parametrize("failure", ["stat", "header", "read_text"])
def test_yaml_tracked_unreadable_candidate_is_fatal(tmp_path: Path, monkeypatch, failure: str):
    """A trusted Git inventory is not proof its listed files were inspected.

    Synthetic PermissionError paths deliberately contain a sensitive string:
    it must not appear in the public/internal-error explanation.
    """
    import subprocess
    from sentinel.registry import yaml_loader
    from sentinel.io.git_files import GitFileEnumerationError

    rule, repo, ctx = _yaml_git_test_repo(tmp_path)
    (repo / ".git").mkdir()
    hit = repo / "hit.txt"
    hit.write_text("FORBIDDEN_TOKEN\n", encoding="utf-8")
    clean = repo / "clean.txt"
    clean.write_text("safe content\n", encoding="utf-8")
    monkeypatch.setattr(
        yaml_loader.subprocess, "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=["git"], returncode=0,
            stdout=b"hit.txt\x00clean.txt\x00", stderr=b"",
        ),
    )

    private_diagnostic = "PRIVATE-HOME-PATH-MUST-NOT-LEAK"
    if failure == "stat":
        original = Path.stat

        def fail_stat(self, *args, **kwargs):
            if self == hit:
                raise PermissionError(private_diagnostic)
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", fail_stat)
    elif failure == "header":
        original = Path.open

        def fail_header(self, mode="r", *args, **kwargs):
            if self == hit and mode == "rb":
                raise PermissionError(private_diagnostic)
            return original(self, mode, *args, **kwargs)

        monkeypatch.setattr(Path, "open", fail_header)
    else:
        original = Path.read_text

        def fail_read(self, *args, **kwargs):
            if self == hit:
                raise PermissionError(private_diagnostic)
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", fail_read)

    with pytest.raises(GitFileEnumerationError, match="YAML scan") as exc:
        rule.check(ctx)
    assert private_diagnostic not in str(exc.value)
    # The CLI reports an internal-error traceback. It must not reveal the
    # underlying PermissionError's private filesystem diagnostic either.
    import traceback
    rendered = "".join(traceback.format_exception(exc.type, exc.value, exc.tb))
    assert private_diagnostic not in rendered


def test_yaml_git_tracked_missing_worktree_file_remains_clean(tmp_path: Path, monkeypatch):
    """An unstaged deletion is routine, unlike an inaccessible tracked file."""
    import subprocess
    from sentinel.registry import yaml_loader

    rule, repo, ctx = _yaml_git_test_repo(tmp_path)
    (repo / ".git").mkdir()
    (repo / "clean.txt").write_text("valid content\n", encoding="utf-8")
    monkeypatch.setattr(
        yaml_loader.subprocess, "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=["git"], returncode=0,
            stdout=b"missing.txt\x00clean.txt\x00", stderr=b"",
        ),
    )
    assert rule.check(ctx) == []
