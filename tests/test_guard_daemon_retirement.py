"""Focused POSIX Guard daemon retirement regressions."""

from __future__ import annotations

import os
import signal
from types import SimpleNamespace

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
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: "linux:terminate-generation")
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: "uid:501")
    monkeypatch.setattr(
        daemon_manager_module,
        "_wait_for_guard_daemon_pid_death",
        lambda _pid: next(waits),
    )
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda _pid, sig: signals.append(sig))

    assert (
        daemon_manager_module._retire_guard_daemon_pid(
            pid,
            expected_start_marker="linux:terminate-generation",
            expected_owner_marker="uid:501",
        )
        is True
    )
    assert signals == [signal.SIGTERM, sigkill]


def test_retirement_process_refuses_missing_generation_marker_for_live_unresolvable_pid(monkeypatch) -> None:
    def retire(*_args, **_kwargs):
        pytest.fail("unbound PID must not be signaled")

    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_command_identity",
        lambda _pid, expected_guard_home=None: None,
    )

    assert daemon_manager_module._retire_guard_daemon_process({"pid": 62_228, "guard_home": "/tmp/guard-home"}) is False


def test_retirement_process_accepts_proven_dead_markerless_pid_without_signaling(monkeypatch) -> None:
    def retire(*_args, **_kwargs):
        pytest.fail("already-dead markerless PID must not be signaled")

    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: True)
    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)

    assert daemon_manager_module._retire_guard_daemon_process({"pid": 62_229, "guard_home": "/tmp/guard-home"}) is True


def test_posix_retirement_refuses_unbound_live_pid_before_signaling(monkeypatch) -> None:
    pid = 62_240
    signals: list[int] = []
    monkeypatch.setattr(daemon_manager_module, "os", _PosixOSProxy())
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda *_args: True)
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: "linux:live-generation")
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: "uid:501")
    monkeypatch.setattr(daemon_manager_module, "_wait_for_guard_daemon_pid_death", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda _pid, sig: signals.append(sig))

    assert daemon_manager_module._retire_guard_daemon_pid(pid) is False
    assert signals == []


def test_generation_retirement_rejects_owner_mismatch_before_signal(monkeypatch) -> None:
    pid = 62_236
    signals: list[int] = []
    monkeypatch.setattr(daemon_manager_module, "os", _PosixOSProxy())
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda *_args: True)
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: "linux:daemon-generation")
    monkeypatch.setattr(
        daemon_manager_module,
        "process_owner_marker",
        lambda candidate: "uid:501" if candidate == os.getpid() else "uid:502",
    )
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda _pid, sig: signals.append(sig))

    assert (
        daemon_manager_module._retire_guard_daemon_pid(
            pid,
            expected_start_marker="linux:daemon-generation",
            expected_owner_marker="uid:501",
        )
        is False
    )
    assert signals == []


def test_authenticated_retirement_forwards_stored_generation_and_owner(
    tmp_path,
    monkeypatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    pid = 62_241
    state = {
        "pid": pid,
        "port": 4781,
        "process_start_marker": "linux:state-generation",
        "user": "uid:501",
    }
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_guard_daemon_pending_launch", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: state)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: True)
    monkeypatch.setattr(daemon_manager_module, "_reconcile_invalid_daemon_lifecycle_artifacts", lambda _home: True)

    def retire(_pid: int, **kwargs: object) -> bool:
        calls.append(kwargs)
        return True

    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)

    assert daemon_manager_module.retire_all_guard_daemons_for_home(guard_home) == [pid]
    assert calls == [
        {
            "expected_guard_home": guard_home,
            "expected_start_marker": "linux:state-generation",
            "expected_owner_marker": "uid:501",
        }
    ]


def test_authenticated_markerless_live_state_is_not_signaled(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    state = {"pid": 62_231, "port": 4781, "guard_home": str(guard_home)}
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: state)
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_guard_daemon_pending_launch", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(
        daemon_manager_module,
        "_retire_guard_daemon_pid",
        lambda *_args, **_kwargs: pytest.fail("markerless live authenticated state must not be signaled"),
    )
    monkeypatch.setattr(daemon_manager_module, "_reconcile_invalid_daemon_lifecycle_artifacts", lambda _home: True)

    assert daemon_manager_module.retire_all_guard_daemons_for_home(guard_home) == []


def test_inventory_retirement_forwards_captured_generation_and_owner(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    pid = 62_242
    calls: list[dict[str, object]] = []
    inventories = iter(([(pid, 4781)], [], []))
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_guard_daemon_pending_launch", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _home: next(inventories),
    )
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: "linux:inventory-generation")
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: "uid:501")
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: True)
    monkeypatch.setattr(daemon_manager_module, "_reconcile_invalid_daemon_lifecycle_artifacts", lambda _home: True)

    def retire(_pid: int, **kwargs: object) -> bool:
        calls.append(kwargs)
        return True

    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)

    assert daemon_manager_module.retire_all_guard_daemons_for_home(guard_home) == [pid]
    assert calls == [
        {
            "expected_guard_home": guard_home,
            "expected_start_marker": "linux:inventory-generation",
            "expected_owner_marker": "uid:501",
        }
    ]


def test_inventory_retirement_skips_process_without_identity_evidence(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    pid = 62_237
    inventories = iter(([(pid, 4781)], [], []))
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_guard_daemon_pending_launch", lambda _home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _home: next(inventories),
    )
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _candidate: None)
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _candidate: "uid:501")
    monkeypatch.setattr(
        daemon_manager_module,
        "_retire_guard_daemon_pid",
        lambda *_args, **_kwargs: pytest.fail("inventory without identity evidence must not be signaled"),
    )
    monkeypatch.setattr(daemon_manager_module, "_reconcile_invalid_daemon_lifecycle_artifacts", lambda _home: True)

    assert daemon_manager_module.retire_all_guard_daemons_for_home(guard_home) == []


def test_duplicate_retirement_forwards_generation_and_owner(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    pid = 62_243
    calls: list[dict[str, object]] = []
    process_lists = iter(([(pid, 4782), (62_244, 4781)], [(62_244, 4781)]))
    monkeypatch.setattr(
        daemon_manager_module,
        "_running_guard_daemon_processes_for_guard_home",
        lambda _home: next(process_lists),
    )
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: "linux:duplicate-generation")
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: "uid:501")
    monkeypatch.setattr(daemon_manager_module, "_rewrite_kept_daemon_state_if_missing", lambda _home, **_kwargs: None)

    def retire(_pid: int, **kwargs: object) -> bool:
        calls.append(kwargs)
        return True

    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)

    daemon_manager_module._retire_duplicate_guard_daemons_unlocked(guard_home, keep_port=4781)
    assert calls == [
        {
            "expected_guard_home": guard_home,
            "expected_start_marker": "linux:duplicate-generation",
            "expected_owner_marker": "uid:501",
        }
    ]


def test_ephemeral_retirement_forwards_generation_and_owner(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "pytest-of-user" / "pytest-1" / "test-case" / "home"
    guard_home.mkdir(parents=True)
    pid = 62_245
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(daemon_manager_module, "_ephemeral_guard_daemon_state_paths", lambda _root: [])
    monkeypatch.setattr(
        daemon_manager_module,
        "_running_ephemeral_guard_daemon_processes",
        lambda: [(pid, guard_home, 60.0)],
    )
    monkeypatch.setattr(daemon_manager_module, "_ephemeral_guard_home_is_inactive", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: "linux:ephemeral-generation")
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: "uid:501")
    monkeypatch.setattr(daemon_manager_module, "clear_guard_daemon_state", lambda _home: None)

    def retire(_pid: int, **kwargs: object) -> bool:
        calls.append(kwargs)
        return True

    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)
    daemon_manager_module._reap_stale_ephemeral_guard_daemons(force=True)
    assert calls == [
        {
            "expected_guard_home": guard_home,
            "expected_start_marker": "linux:ephemeral-generation",
            "expected_owner_marker": "uid:501",
        }
    ]


def test_posix_daemon_retirement_bounds_both_escalation_waits(monkeypatch) -> None:
    pid = 62_225
    signals: list[int] = []
    waits: list[float] = []
    sigkill = getattr(signal, "SIGKILL", 9)

    monkeypatch.setattr(daemon_manager_module, "os", _PosixOSProxy())
    monkeypatch.setattr(daemon_manager_module.signal, "SIGKILL", sigkill, raising=False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda *_args: True)
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: "linux:bounded-generation")
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: "uid:501")
    clock = {"value": 100.0}
    monkeypatch.setattr(daemon_manager_module.time, "monotonic", lambda: clock["value"])

    def wait(_pid: int, *, timeout: float = 1.0) -> bool:
        waits.append(timeout)
        if len(waits) == 1:
            clock["value"] += 0.20
            return False
        clock["value"] += timeout
        return True

    monkeypatch.setattr(daemon_manager_module, "_wait_for_guard_daemon_pid_death", wait)
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda _pid, sig: signals.append(sig))

    assert (
        daemon_manager_module._retire_guard_daemon_pid(
            pid,
            expected_start_marker="linux:bounded-generation",
            expected_owner_marker="uid:501",
            timeout=0.25,
        )
        is True
    )
    assert signals == [signal.SIGTERM, sigkill]
    assert waits == pytest.approx([0.25, 0.05])
    assert clock["value"] == pytest.approx(100.25)


def test_posix_daemon_retirement_rechecks_generation_before_sigkill(monkeypatch) -> None:
    pid = 62_227
    signals: list[int] = []
    waits: list[float] = []
    sigkill = getattr(signal, "SIGKILL", 9)
    markers = iter(("start-1", "start-2"))

    monkeypatch.setattr(daemon_manager_module, "os", _PosixOSProxy())
    monkeypatch.setattr(daemon_manager_module.signal, "SIGKILL", sigkill, raising=False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda *_args: True)
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: next(markers))
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: "uid:501")
    monkeypatch.setattr(
        daemon_manager_module,
        "_wait_for_guard_daemon_pid_death",
        lambda _pid, *, timeout=1.0: waits.append(timeout) or False,
    )
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda _pid, sig: signals.append(sig))

    assert (
        daemon_manager_module._retire_guard_daemon_pid(
            pid,
            expected_start_marker="start-1",
            expected_owner_marker="uid:501",
            timeout=0.25,
        )
        is False
    )
    assert signals == [signal.SIGTERM]
    assert waits[0] == pytest.approx(0.25, abs=0.001)


def test_windows_daemon_retirement_passes_remaining_to_exact_generation_termination(monkeypatch) -> None:
    pid = 62_226
    captured: dict[str, object] = {}

    def terminate(process_id: int, creation_time: int, *, timeout: float | None = None) -> bool:
        captured.update(pid=process_id, creation_time=creation_time, timeout=timeout)
        return True

    monkeypatch.setattr(daemon_manager_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(daemon_manager_module, "time", SimpleNamespace(monotonic=lambda: 100.0))
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(daemon_manager_module, "windows_process_creation_time", lambda _pid: 123)
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: "sid:S-1-5-21")
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda *_args: True)
    monkeypatch.setattr(daemon_manager_module, "windows_terminate_process_if_creation_time", terminate)

    assert (
        daemon_manager_module._retire_guard_daemon_pid(
            pid,
            expected_owner_marker="sid:S-1-5-21",
            timeout=0.25,
        )
        is True
    )
    assert captured == {"pid": pid, "creation_time": 123, "timeout": 0.25}


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
