"""Hooks already deployed across the portfolio stay managed by Sentinel.

Census of live repositories, 2026-11-07: 52 installed pre-push hooks, four
distinct generations once line endings are normalised, ALL of them CRLF on
disk. An exact match on the current script therefore refused every one, so
neither `install-hook` nor `uninstall-hook` could reach a single deployed
repository.

The fixtures are the scripts each generation's payload.py produced, recovered
from history. The digests are pinned here rather than imported from the
installer so that a fixture and an accepted digest cannot drift together.
"""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from sentinel.hook.installer import HookInstallError, install_hook, is_sentinel_hook, uninstall_hook
from sentinel.hook.payload import SENTINEL_MARKER, make_hook_script

FIXTURES = Path(__file__).parents[1] / "fixtures" / "hooks"

# (fixture named for its payload.py commit and mode, sha256 of the LF script)
GENERATIONS = [
    ("pre-push-7f3f0e5-warn.txt",
     "b23610d6d52cf0bf3a3a846f619ca70be53c9aeed54e883d7fe76545742e543b"),
    ("pre-push-7f3f0e5-block.txt",
     "abb3a02821e62b50b0168a8b097a8bb73f63a58770bdeaecab81b7ebdc86e4f2"),
    ("pre-push-f83145f-block.txt",
     "53fa825ade871dae76197a9e6cc98e7eb01f8b5b7ee840da36c103e03e155e70"),
    ("pre-push-abb6ddb-warn.txt",
     "460538d0a6c298b8178e24f64a6c3688d681d9ffb024d70a76f6b78b04874ba1"),
]
IDS = [g[0].removeprefix("pre-push-").removesuffix(".txt") for g in GENERATIONS]


def _repo(tmp_path: Path) -> tuple[Path, Path, Path]:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    hooks = repo / ".git" / "hooks"
    return repo, hooks / "pre-push", hooks / "pre-push.sentinel-backup"


def _crlf(lf: bytes) -> bytes:
    return lf.replace(b"\n", b"\r\n")


@pytest.mark.parametrize(("fixture", "digest"), GENERATIONS, ids=IDS)
def test_fixture_is_the_recovered_generation(fixture: str, digest: str) -> None:
    body = (FIXTURES / fixture).read_bytes()
    assert b"\r" not in body
    assert hashlib.sha256(body).hexdigest() == digest
    assert SENTINEL_MARKER.encode("utf-8") in body


@pytest.mark.parametrize("line_ending", [bytes, _crlf], ids=["lf", "crlf"])
@pytest.mark.parametrize(("fixture", "digest"), GENERATIONS, ids=IDS)
def test_generation_is_recognised(
    tmp_path: Path, fixture: str, digest: str, line_ending,
) -> None:
    _, hook, _ = _repo(tmp_path)
    hook.write_bytes(line_ending((FIXTURES / fixture).read_bytes()))
    assert is_sentinel_hook(hook)


@pytest.mark.parametrize("line_ending", [bytes, _crlf], ids=["lf", "crlf"])
@pytest.mark.parametrize(("fixture", "digest"), GENERATIONS, ids=IDS)
def test_install_upgrades_generation_without_backing_it_up(
    tmp_path: Path, fixture: str, digest: str, line_ending,
) -> None:
    repo, hook, backup = _repo(tmp_path)
    hook.write_bytes(line_ending((FIXTURES / fixture).read_bytes()))
    install_hook(repo, mode="warn")
    assert hook.read_bytes() == make_hook_script("warn").encode("utf-8")
    # A backup would chain the old Sentinel hook behind the new one, which
    # then runs the scan twice and can recurse through its own backup.
    assert not backup.exists()


@pytest.mark.parametrize("line_ending", [bytes, _crlf], ids=["lf", "crlf"])
@pytest.mark.parametrize(("fixture", "digest"), GENERATIONS, ids=IDS)
def test_uninstall_removes_generation(
    tmp_path: Path, fixture: str, digest: str, line_ending,
) -> None:
    repo, hook, backup = _repo(tmp_path)
    hook.write_bytes(line_ending((FIXTURES / fixture).read_bytes()))
    uninstall_hook(repo)
    assert not hook.exists()
    assert not backup.exists()


@pytest.mark.parametrize("line_ending", [bytes, _crlf], ids=["lf", "crlf"])
@pytest.mark.parametrize("operation", [install_hook, uninstall_hook])
@pytest.mark.parametrize(("fixture", "digest"), GENERATIONS, ids=IDS)
def test_user_edited_generation_is_still_refused(
    tmp_path: Path, fixture: str, digest: str, operation, line_ending,
) -> None:
    repo, hook, backup = _repo(tmp_path)
    edited = (FIXTURES / fixture).read_bytes().replace(
        b"#!/bin/sh\n", b"#!/bin/sh\necho local-user-edit\n", 1,
    )
    payload = line_ending(edited)
    hook.write_bytes(payload)

    assert not is_sentinel_hook(hook)
    with pytest.raises(HookInstallError, match="unrecognized or modified"):
        operation(repo)
    assert hook.read_bytes() == payload
    assert not backup.exists()


def test_normalisation_does_not_accept_a_hook_differing_only_in_whitespace(
    tmp_path: Path,
) -> None:
    """Only CRLF is normalised; anything else is a different script."""
    repo, hook, _ = _repo(tmp_path)
    body = (FIXTURES / GENERATIONS[0][0]).read_bytes()
    hook.write_bytes(body + b"\n")
    assert not is_sentinel_hook(hook)
    with pytest.raises(HookInstallError):
        install_hook(repo)
