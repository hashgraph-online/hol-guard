"""Focused POSIX Guard daemon retirement regressions."""

from __future__ import annotations

import os
import signal

import pytest

from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module


class _PosixOSProxy:
    """Expose POSIX branching without mutating process-wide ``os.name``."""

    name = "posix"

    def __getattr__(self, name: str):
        return getattr(os, name)


def test_posix_daemon_retirement_waits_for_sigkill_to_finish(monkeypatch) -> None:
    pid = 62_223
    signals: list[int] = []
    waits = iter((False, True))
    sigkill = getattr(signal, "SIGKILL", 9)

    monkeypatch.setattr(daemon_manager_module, "os", _PosixOSProxy())
    monkeypatch.setattr(daemon_manager_module.signal, "SIGKILL", sigkill, raising=False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda *_args: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_wait_for_guard_daemon_pid_death",
        lambda _pid: next(waits),
    )
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda _pid, sig: signals.append(sig))

    assert daemon_manager_module._retire_guard_daemon_pid(pid) is True
    assert signals == [signal.SIGTERM, sigkill]


@pytest.mark.parametrize("failing_signal", (signal.SIGTERM, getattr(signal, "SIGKILL", 9)))
def test_posix_daemon_retirement_does_not_accept_signal_permission_error(monkeypatch, failing_signal) -> None:
    pid = 62_224
    sigkill = getattr(signal, "SIGKILL", 9)

    monkeypatch.setattr(daemon_manager_module, "os", _PosixOSProxy())
    monkeypatch.setattr(daemon_manager_module.signal, "SIGKILL", sigkill, raising=False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda *_args: True)
    monkeypatch.setattr(daemon_manager_module, "_wait_for_guard_daemon_pid_death", lambda _pid: False)

    def deny_signal(_pid: int, sent_signal: int) -> None:
        if sent_signal == failing_signal:
            raise PermissionError("signal denied")

    monkeypatch.setattr(daemon_manager_module.os, "kill", deny_signal)

    assert daemon_manager_module._retire_guard_daemon_pid(pid) is False
