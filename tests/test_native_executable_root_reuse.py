"""The verified runtime copy is reused only while it still holds exactly the verified bytes."""

from __future__ import annotations

import os
import subprocess

import pytest

from codex_plugin_scanner.guard.extension_builder import native_executable_root as root_module

_SCRIPT = b"#!/bin/sh\necho verified\n"
_OTHER = b"#!/bin/sh\necho other\n"


def _materializations(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    made: list[bytes] = []
    real = root_module._materialize

    def materialize(raw: bytes):
        made.append(raw)
        return real(raw)

    monkeypatch.setattr(root_module, "_materialize", materialize)
    return made


def test_identical_bytes_reuse_one_copy_until_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    made = _materializations(monkeypatch)
    with root_module.verified_executable(_SCRIPT) as first:
        pass
    with root_module.verified_executable(_SCRIPT) as second:
        assert second.read_bytes() == _SCRIPT
    assert first == second
    assert made == [_SCRIPT]
    assert first.exists()

    root_module.release_copies()
    assert not first.parent.exists()


@pytest.mark.skipif(os.name == "nt", reason="runs a POSIX shell script")
def test_a_tampered_copy_is_replaced_and_never_run(monkeypatch: pytest.MonkeyPatch) -> None:
    made = _materializations(monkeypatch)
    with root_module.verified_executable(_SCRIPT) as first:
        pass
    first.write_bytes(b"#!/bin/sh\necho swapped\n")

    with root_module.verified_executable(_SCRIPT) as second:
        completed = subprocess.run([str(second)], capture_output=True, check=True)
    assert second != first
    assert completed.stdout == b"verified\n"
    assert made == [_SCRIPT, _SCRIPT]

    root_module.release_copies()
    assert not first.parent.exists()
    assert not second.parent.exists()


def test_a_missing_copy_or_different_bytes_get_a_fresh_copy(monkeypatch: pytest.MonkeyPatch) -> None:
    made = _materializations(monkeypatch)
    with root_module.verified_executable(_SCRIPT) as first:
        pass
    first.unlink()
    with root_module.verified_executable(_SCRIPT) as second:
        assert second.read_bytes() == _SCRIPT
    with root_module.verified_executable(_OTHER) as third:
        assert third.read_bytes() == _OTHER
    assert len({first, second, third}) == 3
    assert made == [_SCRIPT, _SCRIPT, _OTHER]

    root_module.release_copies()
    assert not any(path.parent.exists() for path in (first, second, third))


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory modes")
def test_a_copy_whose_directory_was_opened_up_is_replaced(monkeypatch: pytest.MonkeyPatch) -> None:
    made = _materializations(monkeypatch)
    with root_module.verified_executable(_SCRIPT) as first:
        pass
    first.parent.chmod(0o755)
    with root_module.verified_executable(_SCRIPT) as second:
        pass
    assert second != first
    assert made == [_SCRIPT, _SCRIPT]
    root_module.release_copies()
    assert not first.parent.exists()


def test_a_failed_replacement_keeps_nothing_half_retired(monkeypatch: pytest.MonkeyPatch) -> None:
    with root_module.verified_executable(_SCRIPT) as first:
        pass

    def fail(raw: bytes):
        raise root_module.ExecutableMaterializationError("no private directory")

    monkeypatch.setattr(root_module, "_materialize", fail)
    with pytest.raises(root_module.ExecutableMaterializationError), root_module.verified_executable(_OTHER):
        pass
    assert root_module._retired == []
    root_module.release_copies()
    assert not first.parent.exists()


def test_a_new_copy_removes_copies_whose_owner_has_ended(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    abandoned = tmp_path / f"{root_module._DIRECTORY_PREFIX}41-old"
    running = tmp_path / f"{root_module._DIRECTORY_PREFIX}42-live"
    unrelated = tmp_path / f"{root_module._DIRECTORY_PREFIX}legacy"
    for directory in (abandoned, running, unrelated):
        directory.mkdir(mode=0o700)
        (directory / "hol-guard-runtime").write_bytes(_SCRIPT)
    monkeypatch.setattr(root_module, "_owner_running", lambda pid: pid == 42)
    monkeypatch.setattr(root_module.tempfile, "tempdir", str(tmp_path))

    with root_module.verified_executable(_SCRIPT) as path:
        assert path.parent.name.startswith(f"{root_module._DIRECTORY_PREFIX}{os.getpid()}-")
    assert not abandoned.exists()
    assert running.exists() and unrelated.exists()
    root_module.release_copies()


@pytest.mark.skipif(os.name == "nt", reason="Windows asks the kernel for a process handle")
def test_an_owner_that_cannot_be_proven_gone_counts_as_running(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(pid: int, signal: int) -> None:
        raise PermissionError

    monkeypatch.setattr(root_module.os, "kill", denied)
    assert root_module._owner_running(12345)


def test_a_replaced_copy_is_removed_once_no_run_uses_it() -> None:
    with root_module.verified_executable(_SCRIPT) as first:
        with root_module.verified_executable(_OTHER) as second:
            # The first copy is still in use by the outer run.
            assert first.exists() and second.exists()
        assert first.exists()
    assert not first.parent.exists()
    assert second.exists()
    assert root_module._retired == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX execute bits")
def test_a_copy_that_lost_its_execute_bit_is_replaced() -> None:
    with root_module.verified_executable(_SCRIPT) as first:
        pass
    first.chmod(0o600)
    with root_module.verified_executable(_SCRIPT) as second:
        assert os.access(second, os.X_OK)
    assert second != first and not first.parent.exists()


@pytest.mark.skipif(os.name == "nt", reason="the Guard-home fallback is POSIX only")
def test_a_guard_home_copy_is_not_reused_once_the_home_opens_up(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    home = tmp_path / "guard-home"
    home.mkdir(mode=0o700)
    home.chmod(0o700)
    monkeypatch.setattr(root_module, "_private_roots", [])
    root_module.use_guard_home(home)
    real_candidate = root_module._candidate
    monkeypatch.setattr(
        root_module, "_candidate", lambda raw, parent: None if parent is None else real_candidate(raw, parent)
    )

    with root_module.verified_executable(_SCRIPT) as first:
        assert first.parent.parent == home / "native-exec"
    home.chmod(0o770)
    with pytest.raises(root_module.ExecutableMaterializationError), root_module.verified_executable(_SCRIPT):
        pass
    # Once the home is private again the copy passes every check, bytes included.
    home.chmod(0o700)
    with root_module.verified_executable(_SCRIPT) as second:
        assert second == first
