"""Runtime heartbeat registration persistence and revocation tests."""

from __future__ import annotations

from pathlib import Path

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
