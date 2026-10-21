"""Runtime heartbeat registration persistence and revocation tests."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import final

from codex_plugin_scanner.guard.daemon.runtime_heartbeat import RuntimeHeartbeatWriter
from codex_plugin_scanner.guard.models import GuardRuntimeRegistration
from codex_plugin_scanner.guard.store import GuardStore
from tests.runtime_registration_support import (
    T0,
    T1,
    delete_runtime_row,
    registration,
)


def test_heartbeat_recreates_missing_runtime_row_with_registration(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    store.upsert_runtime_state(
        session_id="daemon-1",
        daemon_host="127.0.0.1",
        daemon_port=9100,
        started_at=T0,
        last_heartbeat_at=T0,
    )
    delete_runtime_row(store)
    assert store.get_runtime_state() is None

    assert store.try_touch_runtime_state(
        session_id="daemon-1",
        last_heartbeat_at=T1,
        timeout_seconds=1.0,
        registration=registration(),
    )

    assert store.get_runtime_state() == {
        "session_id": "daemon-1",
        "daemon_host": "127.0.0.1",
        "daemon_port": 9100,
        "started_at": T0,
        "last_heartbeat_at": T1,
        "approval_center_url": "http://127.0.0.1:9100",
    }


def test_heartbeat_without_registration_leaves_missing_row_absent(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    store.upsert_runtime_state(
        session_id="daemon-1",
        daemon_host="127.0.0.1",
        daemon_port=9100,
        started_at=T0,
        last_heartbeat_at=T0,
    )
    delete_runtime_row(store)

    assert store.try_touch_runtime_state(
        session_id="daemon-1",
        last_heartbeat_at=T1,
        timeout_seconds=1.0,
    )
    assert store.get_runtime_state() is None


def test_heartbeat_registration_never_steals_a_foreign_session_row(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    store.upsert_runtime_state(
        session_id="other-session",
        daemon_host="127.0.0.1",
        daemon_port=9200,
        started_at=T0,
        last_heartbeat_at=T0,
    )

    assert store.try_touch_runtime_state(
        session_id="daemon-1",
        last_heartbeat_at=T1,
        timeout_seconds=1.0,
        registration=registration(),
    )

    state = store.get_runtime_state()
    assert state is not None
    assert state["session_id"] == "other-session"
    assert state["daemon_port"] == 9200
    assert state["last_heartbeat_at"] == T0


def test_heartbeat_writer_passes_registration_to_the_store() -> None:
    @final
    class RecordingStore:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def try_touch_runtime_state(
            self,
            *,
            session_id: str,
            last_heartbeat_at: str,
            timeout_seconds: float,
            registration: GuardRuntimeRegistration | None = None,
        ) -> bool:
            self.calls.append(
                {
                    "session_id": session_id,
                    "last_heartbeat_at": last_heartbeat_at,
                    "timeout_seconds": timeout_seconds,
                    "registration": registration,
                }
            )
            return True

    store = RecordingStore()
    writer = RuntimeHeartbeatWriter(
        store=store,
        session_id="session",
        write_timeout_seconds=0.01,
        retry_interval_seconds=0.01,
    )
    registration_identity = registration()
    writer.register(registration_identity)
    writer.start()
    try:
        writer.touch("heartbeat-1")
        deadline = time.monotonic() + 1
        while not store.calls and time.monotonic() < deadline:
            time.sleep(0.005)
    finally:
        writer.stop()

    assert len(store.calls) == 1
    assert store.calls[0]["registration"] == registration_identity


def test_heartbeat_writer_stops_inserting_after_clear_registration() -> None:
    @final
    class RecordingStore:
        def __init__(self) -> None:
            self.calls: list[GuardRuntimeRegistration | None] = []

        def try_touch_runtime_state(
            self,
            *,
            session_id: str,
            last_heartbeat_at: str,
            timeout_seconds: float,
            registration: GuardRuntimeRegistration | None = None,
        ) -> bool:
            self.calls.append(registration)
            return True

    store = RecordingStore()
    writer = RuntimeHeartbeatWriter(
        store=store,
        session_id="session",
        write_timeout_seconds=0.01,
        retry_interval_seconds=0.01,
    )
    writer.register(registration())
    writer.clear_registration()
    writer.start()
    try:
        writer.touch("heartbeat-1")
        deadline = time.monotonic() + 1
        while not store.calls and time.monotonic() < deadline:
            time.sleep(0.005)
    finally:
        writer.stop()

    assert store.calls == [None]


def test_clear_registration_waits_for_an_in_flight_write() -> None:
    @final
    class BlockingStore:
        def __init__(self) -> None:
            self.entered = threading.Event()
            self.release = threading.Event()
            self.registrations: list[GuardRuntimeRegistration | None] = []

        def try_touch_runtime_state(
            self,
            *,
            session_id: str,
            last_heartbeat_at: str,
            timeout_seconds: float,
            registration: GuardRuntimeRegistration | None = None,
        ) -> bool:
            self.registrations.append(registration)
            self.entered.set()
            self.release.wait(timeout=5)
            return True

    store = BlockingStore()
    writer = RuntimeHeartbeatWriter(
        store=store,
        session_id="session",
        write_timeout_seconds=0.01,
        retry_interval_seconds=0.01,
    )
    writer.register(registration())
    writer.start()
    try:
        writer.touch("heartbeat-1")
        assert store.entered.wait(timeout=2)

        cleared = threading.Event()

        def clear() -> None:
            writer.clear_registration()
            cleared.set()

        clearing = threading.Thread(target=clear)
        clearing.start()
        assert not cleared.wait(timeout=0.1), "clear_registration must wait for the in-flight write"
        store.release.set()
        clearing.join(timeout=2)
        assert cleared.is_set()

        writer.touch("heartbeat-2")
        deadline = time.monotonic() + 2
        while len(store.registrations) < 2 and time.monotonic() < deadline:
            time.sleep(0.005)
    finally:
        writer.stop()

    assert len(store.registrations) == 2
    assert store.registrations[1] is None, "writes after clear_registration carry no registration"


def test_heartbeat_start_is_noop_after_stop_until_registered() -> None:
    @final
    class RecordingStore:
        def __init__(self) -> None:
            self.calls: list[GuardRuntimeRegistration | None] = []

        def try_touch_runtime_state(
            self,
            *,
            session_id: str,
            last_heartbeat_at: str,
            timeout_seconds: float,
            registration: GuardRuntimeRegistration | None = None,
        ) -> bool:
            self.calls.append(registration)
            return True

    store = RecordingStore()
    writer = RuntimeHeartbeatWriter(
        store=store,
        session_id="session",
        write_timeout_seconds=0.01,
        retry_interval_seconds=0.01,
    )
    writer.register(registration())
    writer.start()
    writer.touch("heartbeat-1")
    deadline = time.monotonic() + 2
    while not store.calls and time.monotonic() < deadline:
        time.sleep(0.005)
    assert len(store.calls) == 1
    assert writer.stop()

    # A completed stop is final: a bare start() must not revive the writer.
    writer.start()
    writer.touch("heartbeat-2")
    time.sleep(0.05)
    assert len(store.calls) == 1

    # Re-arming for a new ownership generation happens through register().
    writer.register(registration())
    writer.start()
    writer.touch("heartbeat-2")
    deadline = time.monotonic() + 2
    while len(store.calls) < 2 and time.monotonic() < deadline:
        time.sleep(0.005)
    try:
        assert len(store.calls) == 2
    finally:
        writer.stop()
