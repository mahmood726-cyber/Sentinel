"""Real pre-push contracts: every remote is a temporary local bare repo."""
from pathlib import Path
import subprocess

import pytest

from sentinel.hook.installer import install_hook


@pytest.fixture
def push_repo(tmp_path, monkeypatch):
    source = Path(__file__).resolve().parents[2]
    monkeypatch.setenv("PYTHONPATH", str(source))
    monkeypatch.setenv("PYTHONIOENCODING", "utf-8")
    for key in ("SENTINEL_BYPASS", "SENTINEL_MODE", "SENTINEL_DIFF_BASE"):
        monkeypatch.delenv(key, raising=False)
    repo = tmp_path / "repo"
    repo.mkdir()
    remote = tmp_path / "remote.git"
    git(repo, "init", "-b", "main")
    git(repo, "init", "--bare", "-b", "main", str(remote))
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "Hook Test")
    git(repo, "config", "commit.gpgsign", "false")
    git(repo, "remote", "add", "origin", str(remote))
    install_hook(repo)
    yield repo, remote
    assert not list((repo / ".git").glob("sentinel-push-*"))
    assert git(repo, "worktree", "list", "--porcelain").stdout.count("worktree ") == 1


def git(repo, *args, check=True):
    result = subprocess.run(["git", "-C", str(repo), *args],
                            capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=120)
    if check:
        assert result.returncode == 0, result.stdout + result.stderr
    return result


def commit(repo, name, bad=False):
    # Construct the planted defect without embedding a machine-specific path.
    content = 'path = "' + "C:" + "/Users/test/private/input.csv" + '"\n'
    (repo / name).write_text(content if bad else "value = 1\n", encoding="utf-8")
    git(repo, "add", "--", name)
    git(repo, "commit", "-m", name)
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def push(repo, *refs, blocked=False):
    result = git(repo, "push", "origin", *refs, check=False)
    output = result.stdout + result.stderr
    if blocked:
        assert result.returncode != 0, output
        assert "hardcoded-local-path" in output, output
    else:
        assert result.returncode == 0, output
    return output


@pytest.mark.parametrize("bad_index", [0, 1])
def test_first_push_checks_non_tip_commits(push_repo, bad_index):
    repo, remote = push_repo
    for i in range(3):
        commit(repo, f"file{i}.py", bad=i == bad_index)
    push(repo, "main", blocked=True)
    assert not git(remote, "show-ref", check=False).stdout


def test_non_checked_out_branch_is_scanned(push_repo):
    repo, _ = push_repo
    commit(repo, "clean.py")
    git(repo, "checkout", "-b", "other")
    commit(repo, "bad.py", bad=True)
    git(repo, "checkout", "main")
    push(repo, "other", blocked=True)


def test_clean_other_branch_ignores_dirty_checkout(push_repo):
    repo, _ = push_repo
    commit(repo, "clean.py")
    git(repo, "branch", "other")
    commit(repo, "bad.py", bad=True)
    push(repo, "other")


def test_deletion_scans_nothing(push_repo):
    repo, remote = push_repo
    commit(repo, "clean.py")
    push(repo, "main:obsolete")
    commit(repo, "bad.py", bad=True)
    output = push(repo, ":obsolete")
    assert "BLOCK=1" not in output
    assert not git(remote, "show-ref", "refs/heads/obsolete", check=False).stdout


def test_all_refs_are_scanned(push_repo):
    repo, _ = push_repo
    commit(repo, "clean.py")
    git(repo, "checkout", "-b", "other")
    commit(repo, "bad.py", bad=True)
    git(repo, "checkout", "main")
    push(repo, "main", "other", blocked=True)


def test_clean_push_without_upstream(push_repo):
    repo, remote = push_repo
    sha = commit(repo, "clean.py")
    push(repo, "main")
    assert git(remote, "rev-parse", "refs/heads/main").stdout.strip() == sha
    assert git(repo, "rev-parse", "@{upstream}", check=False).returncode != 0


def test_uncommitted_fix_cannot_hide_pushed_defect(push_repo):
    repo, _ = push_repo
    commit(repo, "bad.py", bad=True)
    (repo / "bad.py").write_text("value = 1\n", encoding="utf-8")
    push(repo, "main", blocked=True)


def seed_remote(repo, *refs):
    """Arrange an existing remote baseline without running the hook under test."""
    hooks = repo / ".git" / "empty-hooks"
    hooks.mkdir(exist_ok=True)
    git(repo, "-c", f"core.hooksPath={hooks.as_posix()}", "push", "origin", *refs)


@pytest.mark.parametrize("default", ["main", "trunk"])
def test_new_ref_uses_default_branch_merge_base(push_repo, default):
    repo, remote = push_repo
    commit(repo, "baseline.py", bad=True)
    git(remote, "symbolic-ref", "HEAD", f"refs/heads/{default}")
    if default != "main":
        git(repo, "branch", "-m", default)
    seed_remote(repo, default)
    git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", f"refs/remotes/origin/{default}")
    git(repo, "branch", "feature")
    commit(repo, "baseline.py")
    seed_remote(repo, default)
    git(repo, "checkout", "feature")
    commit(repo, "feature.py")
    push(repo, "feature")


def test_force_push_compares_exact_remote_tip(push_repo):
    repo, _ = push_repo
    old = commit(repo, "baseline.py", bad=True)
    seed_remote(repo, "main")
    commit(repo, "baseline.py")
    push(repo, "main")
    push(repo, "--force", f"{old}:refs/heads/main", blocked=True)


def test_multi_ref_reports_both_defects(push_repo):
    repo, _ = push_repo
    commit(repo, "clean.py")
    git(repo, "checkout", "-b", "first")
    commit(repo, "first.py", bad=True)
    git(repo, "checkout", "main")
    git(repo, "checkout", "-b", "second")
    commit(repo, "second.py", bad=True)
    git(repo, "checkout", "main")
    output = push(repo, "first", "second", blocked=True)
    assert "first.py" in output and "second.py" in output


def test_chained_hook_receives_original_ref_records(push_repo):
    repo, _ = push_repo
    sha = commit(repo, "clean.py")
    backup = repo / ".git" / "hooks" / "pre-push.sentinel-backup"
    backup.write_text('#!/bin/sh\ncat > received.txt\n', encoding="utf-8", newline="\n")
    backup.chmod(0o755)
    push(repo, "main")
    assert (repo / "received.txt").read_text() == (
        f"refs/heads/main {sha} refs/heads/main {'0' * 40}\n")


def test_unknown_remote_commit_is_internal_error_even_in_warn_mode(push_repo, monkeypatch):
    repo, remote = push_repo
    commit(repo, "clean.py")
    push(repo, "main")
    writer = repo.parent / "writer"
    git(repo, "clone", "--branch", "main", str(remote), str(writer))
    git(writer, "config", "user.email", "test@example.invalid")
    git(writer, "config", "user.name", "Hook Test")
    git(writer, "config", "commit.gpgsign", "false")
    commit(writer, "remote.py")
    git(writer, "push", "origin", "main")
    commit(repo, "local.py")
    monkeypatch.setenv("SENTINEL_MODE", "warn")
    result = git(repo, "push", "--force", "origin", "main", check=False)
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "INTERNAL ERROR" in output
    assert "verdicts: BLOCK=0" not in output


def test_hand_written_banner_is_not_trusted_as_a_sentinel_hook(push_repo):
    from sentinel.hook.installer import is_sentinel_hook
    from sentinel.hook.payload import SENTINEL_MARKER

    repo, _ = push_repo
    hook = repo / ".git" / "hooks" / "pre-push"
    hook.write_text(f"#!/bin/sh\n{SENTINEL_MARKER}\nexit 0\n", encoding="utf-8")
    assert not is_sentinel_hook(hook)


def test_old_hook_is_recognised_and_upgraded(push_repo):
    from sentinel.hook.installer import is_sentinel_hook
    from sentinel.hook.payload import HOOK_GENERATION

    # Use the real hook main installed before this change (bcfbafd), not a
    # hand-written banner: the installer only trusts recovered generations.
    old = Path(__file__).parents[1] / "fixtures" / "hooks" / "pre-push-bcfbafd-warn.txt"
    repo, _ = push_repo
    hook = repo / ".git" / "hooks" / "pre-push"
    hook.write_bytes(old.read_bytes())
    assert is_sentinel_hook(hook)
    install_hook(repo)
    assert f"# Sentinel hook generation: {HOOK_GENERATION}" in hook.read_text()
    assert not (hook.parent / "pre-push.sentinel-backup").exists()


def test_scan_error_cleans_snapshot(push_repo, monkeypatch):
    from sentinel.hook.push import scan_push
    from sentinel.registry.registry import Registry

    repo, _ = push_repo
    sha = commit(repo, "clean.py")

    class BrokenRule:
        def check(self, ctx):
            assert git(ctx.repo_root, "rev-parse", "HEAD").stdout.strip() == sha
            raise RuntimeError("planted scanner failure")

    class BrokenRegistry:
        def all_rules(self):
            return [BrokenRule()]

    monkeypatch.setattr(Registry, "from_dir", lambda _: BrokenRegistry())
    with pytest.raises(RuntimeError, match="planted scanner failure"):
        scan_push(repo, "origin", f"refs/heads/main {sha} refs/heads/main {'0' * 40}\n")
    assert not list((repo / ".git").glob("sentinel-push-*"))


def test_default_branch_without_remote_tracking_ref(push_repo):
    repo, _ = push_repo
    commit(repo, "baseline.py", bad=True)
    seed_remote(repo, "main")
    git(repo, "remote", "rename", "origin", "publish")
    git(repo, "update-ref", "-d", "refs/remotes/publish/main")
    git(repo, "checkout", "-b", "feature")
    commit(repo, "feature.py")
    result = git(repo, "push", "publish", "feature", check=False)
    assert result.returncode == 0, result.stdout + result.stderr


def test_unrelated_default_history_scans_full_tree(push_repo):
    repo, _ = push_repo
    commit(repo, "clean.py")
    push(repo, "main")
    git(repo, "checkout", "--orphan", "unrelated")
    git(repo, "rm", "-rf", ".")
    commit(repo, "bad.py", bad=True)
    commit(repo, "tip.py")
    push(repo, "unrelated", blocked=True)


def test_full_override_scans_unchanged_baseline(push_repo, monkeypatch):
    repo, _ = push_repo
    commit(repo, "baseline.py", bad=True)
    seed_remote(repo, "main")
    commit(repo, "tip.py")
    monkeypatch.setenv("SENTINEL_DIFF_BASE", "full")
    push(repo, "main", blocked=True)


def test_malformed_records_return_internal_error(push_repo):
    import sys

    repo, _ = push_repo
    result = subprocess.run([sys.executable, "-m", "sentinel.hook.push", "origin"],
                            cwd=repo, input="malformed\n", text=True,
                            capture_output=True, timeout=120)
    assert result.returncode == 10
    assert "INTERNAL ERROR" in result.stderr
    assert "verdicts:" not in result.stdout


def test_stdin_read_failure_cannot_report_clean(push_repo):
    repo, _ = push_repo
    commit(repo, "clean.py")
    hook = repo / ".git" / "hooks" / "pre-push"
    script = hook.read_text(encoding="utf-8")
    assert "$(cat" in script
    # Fault-inject a failed stdin reader into the installed, otherwise real hook.
    hook.write_text(script.replace("$(cat", "$(false"), encoding="utf-8", newline="\n")
    result = git(repo, "push", "origin", "main", check=False)
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "INTERNAL ERROR" in output
    assert "verdicts:" not in output
