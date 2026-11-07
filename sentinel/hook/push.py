"""Scan the commits described by Git's pre-push stdin, never the checkout."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory

from sentinel.cli.scan import EXIT_INTERNAL_ERROR, RULES_ROOT, _print_summary
from sentinel.core import RepoContext, ScanMode, Severity
from sentinel.io import write_findings
from sentinel.io.git_files import set_path_filter
from sentinel.registry.registry import Registry


def _git(repo: Path, *args: str, allowed=(0,)) -> subprocess.CompletedProcess:
    result = subprocess.run(["git", "-C", str(repo), *args],
                            capture_output=True, timeout=120)
    if result.returncode not in allowed:
        raise RuntimeError(f"git {args[0]} failed ({result.returncode}): "
                           + result.stderr.decode("utf-8", errors="replace"))
    return result


def _commit(repo: Path, ref: str) -> str:
    return _git(repo, "rev-parse", "--verify", "--end-of-options",
                f"{ref}^{{commit}}").stdout.decode("ascii").strip()


def _new_ref_base(repo: Path, remote: str, commit: str) -> str | None:
    # Git's stdin does not include the remote's default branch. Ask for HEAD
    # without fetching objects; a missing local object fails closed in _commit.
    advertised = _git(repo, "ls-remote", "--symref", "--", remote, "HEAD")
    heads = [line.split("\t")[0] for line in
             advertised.stdout.decode("utf-8").splitlines()
             if line.endswith("\tHEAD") and not line.startswith("ref: ")]
    if not heads:
        if advertised.stdout.strip():
            raise ValueError("remote advertised HEAD without an object ID")
        return None
    if len(heads) != 1 or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", heads[0]):
        raise ValueError("invalid remote HEAD advertisement")
    default = _commit(repo, heads[0])
    result = _git(repo, "merge-base", default, commit, allowed=(0, 1))
    # Exit 1 specifically means unrelated histories, not a Git error.
    return result.stdout.decode("ascii").strip() if result.returncode == 0 else None


def _paths(repo: Path, base: str | None, commit: str) -> frozenset[str]:
    if base is None:
        args = ("ls-tree", "-r", "--name-only", "-z", commit)
    else:
        args = ("diff", "--name-only", "-z", "--no-renames", "--diff-filter=d",
                base, commit, "--")
    return frozenset(p for p in _git(repo, *args).stdout.decode("utf-8").split("\0") if p)


@contextmanager
def _snapshot(repo: Path, commit: str):
    git_dir = _git(repo, "rev-parse", "--absolute-git-dir").stdout.decode("utf-8").strip()
    with TemporaryDirectory(prefix="sentinel-push-", dir=git_dir) as temp:
        root = Path(temp)
        tree = root / repo.name
        hooks = root / "hooks"
        hooks.mkdir()
        try:
            _git(repo, "-c", f"core.hooksPath={hooks.as_posix()}",
                 "worktree", "add", "--detach", str(tree), commit)
            yield tree
        finally:
            if (tree / ".git").exists():
                _git(repo, "worktree", "remove", "--force", str(tree))


def scan_push(repo: Path, remote: str, records: str) -> int:
    plans = []
    for line in records.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 4:
            raise ValueError("malformed pre-push ref record")
        local_ref, local_sha, remote_ref, remote_sha = fields
        if any(not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", sha)
               for sha in (local_sha, remote_sha)):
            raise ValueError("invalid pre-push object ID")
        if set(local_sha) == {"0"}:
            continue
        commit = _commit(repo, local_sha)
        base = (_new_ref_base(repo, remote, commit) if set(remote_sha) == {"0"}
                else _commit(repo, remote_sha))
        paths = _paths(repo, base, commit)
        override = os.environ.get("SENTINEL_DIFF_BASE", "")
        if override == "full":
            paths = _paths(repo, None, commit)
        elif override:
            # An override may expand coverage, never hide part of a pushed range.
            paths |= _paths(repo, _commit(repo, override), commit)
        plans.append((remote_ref, commit, base, paths))

    verdicts = []
    registry = Registry.from_dir(RULES_ROOT) if any(p[3] for p in plans) else None
    for remote_ref, commit, base, paths in plans:
        print(f"[Sentinel] push: {remote_ref} {commit} vs {base or 'FULL TREE'} "
              f"({len(paths)} files)")
        if not paths:
            continue
        with _snapshot(repo, commit) as tree:
            set_path_filter(paths)
            try:
                ctx = RepoContext(repo_root=tree, mode=ScanMode.REPO)
                for rule in registry.all_rules():
                    for verdict in rule.check(ctx):
                        file = verdict.file
                        if file and Path(file).is_absolute():
                            file = Path(file).relative_to(tree).as_posix()
                        verdicts.append(replace(
                            verdict, repo=str(repo), file=file,
                            detail=f"[{remote_ref} {commit}] {verdict.detail}"))
            finally:
                set_path_filter(None)
    write_findings(repo, verdicts)
    _print_summary(verdicts)
    return 1 if any(v.severity == Severity.BLOCK for v in verdicts) else 0


def main() -> int:
    try:
        # Git exports repository-local variables to hooks. They must not redirect
        # rule subprocesses from the detached snapshot back into the checkout.
        repo = Path(_git(Path.cwd(), "rev-parse", "--show-toplevel").stdout.decode("utf-8").strip())
        local_vars = _git(repo, "rev-parse", "--local-env-vars").stdout.decode("ascii").splitlines()
        for name in local_vars:
            os.environ.pop(name, None)
        return scan_push(repo, sys.argv[1], sys.stdin.read())
    except Exception as exc:
        print(f"[Sentinel] INTERNAL ERROR: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR


def _terminate(signum, frame):
    raise SystemExit(128 + signum)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _terminate)
    raise SystemExit(main())
