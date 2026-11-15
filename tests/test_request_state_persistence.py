"""A replayed request must not succeed when its consumed nonce cannot be saved."""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.routes import request_state


def test_a_failed_replace_raises_and_leaves_no_temporary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = request_state._ReplayState(tmp_path)

    def refuse(*_args: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(request_state.os, "replace", refuse)
    with pytest.raises(OSError):
        state.set("package_firewall_session_nonces", {"n": 1})
    assert [path.name for path in tmp_path.iterdir() if path.name.startswith(".")] == []


def test_an_oversized_state_raises_instead_of_dropping_the_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = request_state._ReplayState(tmp_path)
    monkeypatch.setattr(request_state, "_STATE_LIMIT_BYTES", 8)
    with pytest.raises(OSError):
        state.set("package_firewall_session_nonces", {"nonce": "consumed"})


def test_a_saved_value_reads_back(tmp_path: Path) -> None:
    state = request_state._ReplayState(tmp_path)
    state.set("package_firewall_session_nonces", {"n": 1})
    assert state.get("package_firewall_session_nonces") == {"n": 1}


class _FakeMsvcrt:
    """msvcrt's byte-range lock, refusing the first ``busy`` attempts as a held range does."""

    LK_NBLCK = 2
    LK_UNLCK = 0

    def __init__(self, busy: int = 0, error: int = errno.EACCES) -> None:
        self.busy = busy
        self.error = error
        self.calls: list[tuple[int, int, int]] = []

    def locking(self, descriptor: int, mode: int, length: int) -> None:
        self.calls.append((mode, os.lseek(descriptor, 0, os.SEEK_CUR), length))
        if mode == self.LK_NBLCK and self.busy:
            self.busy -= 1
            raise OSError(self.error, "locked")


def _as_windows(monkeypatch: pytest.MonkeyPatch, fake: _FakeMsvcrt) -> list[float]:
    sleeps: list[float] = []
    monkeypatch.setattr(request_state, "fcntl", None)
    monkeypatch.setattr(request_state, "msvcrt", fake)
    monkeypatch.setattr(request_state.time, "sleep", sleeps.append)
    return sleeps


def test_a_windows_replay_locks_the_first_byte_and_releases_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeMsvcrt()
    _ = _as_windows(monkeypatch, fake)
    state = request_state._ReplayState(tmp_path)
    state.set("package_firewall_session_nonces", {"n": 1})
    assert state.get("package_firewall_session_nonces") == {"n": 1}
    assert fake.calls == [(fake.LK_NBLCK, 0, 1), (fake.LK_UNLCK, 0, 1)] * 2
    assert (tmp_path / "daemon-replay-state.lock").read_bytes() == b""


def test_a_windows_replay_waits_while_another_holds_the_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeMsvcrt(busy=2, error=errno.EDEADLK)
    sleeps = _as_windows(monkeypatch, fake)
    state = request_state._ReplayState(tmp_path)
    state.set("package_firewall_session_nonces", {"n": 1})
    assert len(sleeps) == 2
    assert [mode for mode, _offset, _length in fake.calls] == [fake.LK_NBLCK] * 3 + [fake.LK_UNLCK]


def test_a_windows_lock_failure_that_is_not_contention_is_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _FakeMsvcrt(busy=1, error=errno.EBADF)
    sleeps = _as_windows(monkeypatch, fake)
    state = request_state._ReplayState(tmp_path)
    with pytest.raises(OSError):
        state.set("package_firewall_session_nonces", {"n": 1})
    assert sleeps == []
    assert not (tmp_path / "daemon-replay-state.json").exists()


def test_a_host_with_no_file_lock_refuses_instead_of_running_unlocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(request_state, "fcntl", None)
    monkeypatch.setattr(request_state, "msvcrt", None)
    state = request_state._ReplayState(tmp_path)
    with pytest.raises(OSError, match="file locking is unavailable"):
        state.set("package_firewall_session_nonces", {"n": 1})
