"""A Guard home keeps one verified runtime copy for later processes, and never runs a copy that differs."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_builder import native_executable_root as root_module

pytestmark = pytest.mark.skipif(os.name == "nt", reason="runs POSIX shell scripts and checks POSIX modes")

_SCRIPT = b"#!/bin/sh\necho verified\n"
_OTHER = b"#!/bin/sh\necho other\n"


def _kept_name(raw: bytes) -> str:
    return root_module._KEPT_PREFIX + hashlib.sha256(raw).hexdigest()


@pytest.fixture
def guard_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "guard-home"
    home.mkdir(mode=0o700)
    home.chmod(0o700)
    monkeypatch.setattr(root_module, "_private_roots", [])
    root_module.use_guard_home(home)
    root_module.release_copies()
    yield home
    root_module.release_copies()


@pytest.fixture
def writes(monkeypatch: pytest.MonkeyPatch) -> list[Path | None]:
    """Every new copy written, by the directory it was written under."""
    made: list[Path | None] = []
    real = root_module._candidate

    def candidate(raw: bytes, parent: Path | None):
        made.append(parent)
        return real(raw, parent)

    monkeypatch.setattr(root_module, "_candidate", candidate)
    return made


def test_a_later_process_runs_the_kept_copy_without_writing_a_new_one(guard_home: Path, writes: list) -> None:
    with root_module.verified_executable(_SCRIPT) as first:
        assert first.parent == guard_home / "native-exec" / _kept_name(_SCRIPT)
        assert stat.S_IMODE(first.parent.lstat().st_mode) == 0o700
    # Process exit.
    root_module.release_copies()
    assert first.read_bytes() == _SCRIPT
    with root_module.verified_executable(_SCRIPT) as second:
        completed = subprocess.run([str(second)], capture_output=True, check=True)
    assert second == first
    assert completed.stdout == b"verified\n"
    assert len(writes) == 1


def test_a_tampered_kept_copy_is_replaced_and_never_run(guard_home: Path, writes: list) -> None:
    with root_module.verified_executable(_SCRIPT) as first:
        pass
    root_module.release_copies()
    first.write_bytes(b"#!/bin/sh\necho swapped\n")
    with root_module.verified_executable(_SCRIPT) as second:
        completed = subprocess.run([str(second)], capture_output=True, check=True)
    assert second == first
    assert completed.stdout == b"verified\n"
    assert len(writes) == 2
    assert [entry.name for entry in (guard_home / "native-exec").iterdir()] == [_kept_name(_SCRIPT)]


def test_a_symlink_in_place_of_the_kept_copy_is_replaced(guard_home: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    (elsewhere / root_module._EXECUTABLE_NAME).write_bytes(_SCRIPT)
    (elsewhere / root_module._EXECUTABLE_NAME).chmod(0o700)
    private = guard_home / "native-exec"
    private.mkdir(mode=0o700)
    (private / _kept_name(_SCRIPT)).symlink_to(elsewhere, target_is_directory=True)
    with root_module.verified_executable(_SCRIPT) as path:
        assert not path.parent.is_symlink()
        assert path.read_bytes() == _SCRIPT
    assert (elsewhere / root_module._EXECUTABLE_NAME).exists()


def test_a_kept_copy_is_not_used_once_its_home_opens_up(guard_home: Path) -> None:
    with root_module.verified_executable(_SCRIPT) as first:
        pass
    root_module.release_copies()
    guard_home.chmod(0o770)
    try:
        with root_module.verified_executable(_SCRIPT) as second:
            assert second.parent.parent != guard_home / "native-exec"
    finally:
        guard_home.chmod(0o700)
    assert first.exists()


def test_a_kept_copy_of_another_runtime_is_removed_only_after_a_day_unused(guard_home: Path) -> None:
    with root_module.verified_executable(_OTHER) as idle:
        pass
    with root_module.verified_executable(_SCRIPT) as recent_other:
        pass
    root_module.release_copies()
    old = time.time() - root_module._KEPT_IDLE_SECONDS - 60
    os.utime(idle.parent, (old, old))
    with root_module.verified_executable(_SCRIPT):
        pass
    assert not idle.parent.exists()
    assert recent_other.exists()

    with root_module.verified_executable(_OTHER) as again:
        pass
    root_module.release_copies()
    with root_module.verified_executable(_SCRIPT):
        pass
    assert again.exists()


def test_a_kept_copy_in_a_home_no_longer_open_is_not_reused(guard_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with root_module.verified_executable(_SCRIPT) as first:
        pass
    monkeypatch.setattr(root_module, "_private_roots", [])
    with root_module.verified_executable(_SCRIPT) as second:
        assert second != first


def test_a_verified_digest_names_the_copy_but_its_bytes_are_still_compared(guard_home: Path, writes: list) -> None:
    digest = hashlib.sha256(_SCRIPT).hexdigest()
    with root_module.verified_executable(_SCRIPT, digest) as first:
        assert first.parent.name == _kept_name(_SCRIPT)
    root_module.release_copies()
    # A copy found under that name with other bytes is replaced, never run.
    first.write_bytes(_OTHER)
    with root_module.verified_executable(_SCRIPT, digest) as second:
        completed = subprocess.run([str(second)], capture_output=True, check=True)
    assert completed.stdout == b"verified\n"
    assert len(writes) == 2


@pytest.mark.parametrize("digest", ["../escape", "A" * 64, "0" * 63])
def test_a_digest_that_is_not_plain_hex_never_becomes_a_path(guard_home: Path, digest: str) -> None:
    with root_module.verified_executable(_SCRIPT, digest) as path:
        assert path.parent == guard_home / "native-exec" / _kept_name(_SCRIPT)
