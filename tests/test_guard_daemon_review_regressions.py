from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager as daemon_manager
from codex_plugin_scanner.guard.daemon import recovery_worker
from codex_plugin_scanner.guard.daemon import server as server_module
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


def test_invalid_remaining_seconds_falls_back_to_valid_milliseconds() -> None:
    payload: dict[str, object] = {
        "guard_remaining_seconds": "invalid",
        "guard_remaining_ms": 1250,
    }

    assert server_module._runtime_hook_remaining_hint(payload) == 1.25  # pyright: ignore[reportPrivateUsage]
    assert "guard_remaining_seconds" not in payload
    assert "guard_remaining_ms" not in payload


@pytest.mark.parametrize("invalid_seconds", (float("nan"), float("inf"), float("-inf")))
def test_nonfinite_remaining_seconds_falls_back_to_valid_milliseconds(invalid_seconds: float) -> None:
    payload: dict[str, object] = {
        "guard_remaining_seconds": invalid_seconds,
        "guard_remaining_ms": 1250,
    }

    assert server_module._runtime_hook_remaining_hint(payload) == 1.25  # pyright: ignore[reportPrivateUsage]


def test_valid_remaining_seconds_consumes_millisecond_fallback() -> None:
    payload: dict[str, object] = {
        "guard_remaining_seconds": 2.0,
        "guard_remaining_ms": 1250,
    }

    assert server_module._runtime_hook_remaining_hint(payload) == 2.0  # pyright: ignore[reportPrivateUsage]
    assert "guard_remaining_ms" not in payload


def test_boolean_deadline_hints_use_default() -> None:
    payload: dict[str, object] = {
        "guard_remaining_seconds": True,
        "guard_remaining_ms": False,
    }

    assert server_module._runtime_hook_remaining_hint(payload) == (  # pyright: ignore[reportPrivateUsage]
        server_module._RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS  # pyright: ignore[reportPrivateUsage]
    )


def test_recovery_worker_clears_its_claim_when_recovery_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    cleared: list[tuple[Path, str]] = []
    monkeypatch.setattr(
        recovery_worker,
        "recover_guard_daemon_after_hook_failure",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("recovery failed")),
    )
    monkeypatch.setattr(
        recovery_worker,
        "clear_guard_daemon_recovery_reservation",
        lambda home, *, token: cleared.append((home, token)) or True,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "recovery_worker",
            str(guard_home),
            str(tmp_path),
            "transport-failure",
            "recovery-token",
        ],
    )

    with pytest.raises(RuntimeError, match="recovery failed"):
        recovery_worker.main()

    assert cleared == [(guard_home, "recovery-token")]


def test_recovery_reservation_keeps_live_worker_owner_past_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    claimed_at = time.time()
    monkeypatch.setattr(daemon_manager.time, "time", lambda: claimed_at)
    token = daemon_manager._claim_guard_daemon_recovery_reservation(guard_home)  # pyright: ignore[reportPrivateUsage]
    assert token is not None
    monkeypatch.setattr(
        daemon_manager,
        "_guard_daemon_pid_is_running",
        lambda pid: pid == 42,
    )
    assert daemon_manager._bind_guard_daemon_recovery_reservation(  # pyright: ignore[reportPrivateUsage]
        guard_home,
        token=token,
        pid=42,
    )

    monkeypatch.setattr(daemon_manager.time, "time", lambda: claimed_at + 31.0)
    assert daemon_manager._claim_guard_daemon_recovery_reservation(guard_home) is None  # pyright: ignore[reportPrivateUsage]

    monkeypatch.setattr(daemon_manager, "_guard_daemon_pid_is_running", lambda _pid: False)
    replacement = daemon_manager._claim_guard_daemon_recovery_reservation(guard_home)  # pyright: ignore[reportPrivateUsage]
    assert replacement is not None and replacement != token


def test_recovery_reservation_rejects_reused_pid_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    claimed_at = time.time()
    clock = [claimed_at]
    command = "python recovery-worker"
    start_marker = "linux:worker-generation-a"
    monkeypatch.setattr(daemon_manager.time, "time", lambda: clock[0])
    monkeypatch.setattr(daemon_manager, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(daemon_manager, "_guard_daemon_command_for_pid", lambda _pid: command)
    monkeypatch.setattr(daemon_manager, "process_start_token", lambda _pid: start_marker)

    token = daemon_manager._claim_guard_daemon_recovery_reservation(guard_home)  # pyright: ignore[reportPrivateUsage]
    assert token is not None
    assert daemon_manager._bind_guard_daemon_recovery_reservation(  # pyright: ignore[reportPrivateUsage]
        guard_home,
        token=token,
        pid=4242,
    )
    reservation = daemon_manager._load_guard_daemon_recovery_reservation(guard_home)  # pyright: ignore[reportPrivateUsage]
    assert isinstance(reservation, dict)
    assert daemon_manager._guard_daemon_recovery_owner_state(reservation) is True  # pyright: ignore[reportPrivateUsage]

    monkeypatch.setattr(daemon_manager, "_guard_daemon_command_for_pid", lambda _pid: "python unrelated")
    assert daemon_manager._guard_daemon_recovery_owner_state(reservation) is False  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(daemon_manager, "_guard_daemon_command_for_pid", lambda _pid: command)
    monkeypatch.setattr(daemon_manager, "process_start_token", lambda _pid: "linux:worker-generation-b")
    assert daemon_manager._guard_daemon_recovery_owner_state(reservation) is False  # pyright: ignore[reportPrivateUsage]

    clock[0] += 31.0
    replacement = daemon_manager._claim_guard_daemon_recovery_reservation(guard_home)  # pyright: ignore[reportPrivateUsage]
    assert replacement is not None and replacement != token


def test_recovery_scheduler_contains_worker_when_reservation_bind_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    guard_home.mkdir()
    home_dir.mkdir()
    signals: list[tuple[int, int]] = []

    class FakeProcess:
        pid = 4243

        def __init__(self) -> None:
            self.reaped = False

        def poll(self) -> int | None:
            return 0 if self.reaped else None

        def wait(self, *, timeout: float) -> int:
            del timeout
            self.reaped = True
            return 0

    process = FakeProcess()
    monkeypatch.setattr(daemon_manager, "_isolated_python_module_command", lambda *_args: ["python", "worker"])
    monkeypatch.setattr(daemon_manager, "_daemon_launcher_env", lambda **_kwargs: {})
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        daemon_manager,
        "_bind_guard_daemon_recovery_reservation",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("bind failed")),
    )
    monkeypatch.setattr(daemon_manager.os, "killpg", lambda pid, sig: signals.append((pid, sig)))

    daemon_manager.schedule_guard_daemon_recovery(
        guard_home,
        home_dir=home_dir,
        failure_kind="transport-failure",
    )

    assert process.reaped is True
    assert signals == [(4243, daemon_manager.signal.SIGTERM)]
    assert daemon_manager._load_guard_daemon_recovery_reservation(guard_home) == {}  # pyright: ignore[reportPrivateUsage]


def test_recovery_worker_thread_lock_timeout_is_bounded(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    with daemon_manager._guard_daemon_recovery_lock(guard_home):  # pyright: ignore[reportPrivateUsage]
        started = time.monotonic()
        with (
            pytest.raises(RuntimeError, match="recovery ownership"),
            daemon_manager._guard_daemon_recovery_lock(  # pyright: ignore[reportPrivateUsage]
                guard_home,
                timeout_seconds=0.02,
            ),
        ):
            pass
        assert time.monotonic() - started < 0.5


def test_recovery_worker_file_lock_timeout_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(daemon_manager, "_try_lock_daemon_file", lambda _handle: False)
    started = time.monotonic()
    with (
        pytest.raises(RuntimeError, match="recovery ownership"),
        daemon_manager._guard_daemon_recovery_lock(  # pyright: ignore[reportPrivateUsage]
            guard_home,
            timeout_seconds=0.02,
        ),
    ):
        pass
    assert time.monotonic() - started < 0.5


def test_recovery_scheduler_respects_explicitly_off_protection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text(
        'mode = "observe"\nprotection_posture = "watch"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("disabled protection must not restart a recovery worker"),
    )

    daemon_manager.schedule_guard_daemon_recovery(
        guard_home,
        failure_kind="transport-failure",
    )

    assert not (guard_home / "daemon-recovery-reservation.json").exists()


@pytest.mark.parametrize(
    "config_text",
    (
        'mode = "observe"\nprotection_posture = "protected"\n',
        'mode = "enforce"\nprotection_posture = "watch"\n',
    ),
)
def test_recovery_worker_stops_when_protection_turns_off(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_text: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text(config_text, encoding="utf-8")
    monkeypatch.setattr(
        daemon_manager,
        "ensure_guard_daemon",
        lambda *_args, **_kwargs: pytest.fail("disabled protection must not ensure a daemon"),
    )

    with pytest.raises(RuntimeError, match="disabled by local protection posture"):
        daemon_manager.recover_guard_daemon_after_hook_failure(
            guard_home,
            failure_kind="transport-failure",
        )


def test_recovery_scheduler_keeps_one_live_worker_past_reservation_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    guard_home.mkdir()
    home_dir.mkdir()
    clock = [100.0]
    spawned: list[object] = []

    class FakeProcess:
        pid = 4242

        def poll(self) -> int | None:
            return None

    monkeypatch.setattr(daemon_manager.time, "time", lambda: clock[0])
    monkeypatch.setattr(daemon_manager, "_guard_daemon_pid_is_running", lambda pid: pid == 4242)
    monkeypatch.setattr(daemon_manager, "_guard_daemon_command_for_pid", lambda _pid: None)
    monkeypatch.setattr(daemon_manager, "process_start_token", lambda _pid: None)
    monkeypatch.setattr(
        daemon_manager,
        "_isolated_python_module_command",
        lambda *_args: ["python", "recovery-worker"],
    )
    monkeypatch.setattr(daemon_manager, "_daemon_launcher_env", lambda **_kwargs: {})
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *_args, **_kwargs: spawned.append(FakeProcess()) or spawned[-1],
    )

    daemon_manager.schedule_guard_daemon_recovery(
        guard_home,
        home_dir=home_dir,
        failure_kind="transport-failure",
    )
    clock[0] += 31.0
    daemon_manager.schedule_guard_daemon_recovery(
        guard_home,
        home_dir=home_dir,
        failure_kind="transport-failure",
    )

    assert len(spawned) == 1


def test_frozen_recovery_scheduler_spawns_private_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    executable = tmp_path / "hol-guard"
    guard_home.mkdir()
    home_dir.mkdir()
    executable.write_bytes(b"frozen")
    spawned: list[tuple[list[str], dict[str, object]]] = []
    monkeypatch.setattr(
        daemon_manager,
        "_claim_guard_daemon_recovery_reservation",
        lambda _guard_home: "recovery-token",
    )
    monkeypatch.setattr(
        daemon_manager,
        "_daemon_launcher_env",
        lambda **_kwargs: {},
    )

    def spawn(command: list[str], **kwargs: object) -> object:
        spawned.append((command, kwargs))
        return object()

    monkeypatch.setattr(subprocess, "Popen", spawn)

    daemon_manager.schedule_guard_daemon_recovery(
        guard_home,
        home_dir=home_dir,
        failure_kind="transport-failure",
        executable=executable,
    )

    assert len(spawned) == 1
    command, kwargs = spawned[0]
    assert command[:2] == [str(executable), "--_hol-guard-codex-daemon-recovery-worker"]
    assert kwargs["start_new_session"] is True


def test_stop_invalidates_owned_service_begin_before_workers_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon = GuardDaemonServer(
        GuardStore(tmp_path / "guard-home"),
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=0,
    )
    original_begin_owned_service = daemon._begin_owned_service
    begin_entered = threading.Event()
    release_begin = threading.Event()
    start_errors: list[BaseException] = []
    stop_errors: list[BaseException] = []

    def delayed_begin_owned_service(generation: int | None = None) -> None:
        begin_entered.set()
        assert release_begin.wait(timeout=5)
        original_begin_owned_service(generation)

    def start_daemon() -> None:
        try:
            daemon.start()
        except BaseException as error:
            start_errors.append(error)

    def stop_daemon() -> None:
        try:
            daemon.stop()
        except BaseException as error:
            stop_errors.append(error)

    monkeypatch.setattr(daemon, "_begin_owned_service", delayed_begin_owned_service)
    starter = threading.Thread(target=start_daemon)
    stopper = threading.Thread(target=stop_daemon)
    try:
        starter.start()
        assert begin_entered.wait(timeout=10)
        stopper.start()
        stopper.join(timeout=0.5)
        assert stopper.is_alive()
        release_begin.set()
        starter.join(timeout=10)
        stopper.join(timeout=10)

        assert not starter.is_alive()
        assert not stopper.is_alive()
        assert stop_errors == []
        assert len(start_errors) == 1
        assert str(start_errors[0]) == "Guard daemon stopped during startup"
        assert daemon._owner_lock is None
        assert daemon._server.hook_process_runner.stats()["workers"] == 0
    finally:
        release_begin.set()
        daemon.stop()
