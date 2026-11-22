"""The daemon runtime row is read and cleared by the native store."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.store import GuardStore


def _upsert(store: GuardStore, session_id: str) -> None:
    store.upsert_runtime_state(
        session_id=session_id,
        daemon_host="127.0.0.1",
        daemon_port=4319,
        started_at="2026-11-22T00:00:00+00:00",
        last_heartbeat_at="2026-11-22T00:00:05+00:00",
    )


def test_no_runtime_row_reads_none(tmp_path: Path) -> None:
    assert GuardStore(tmp_path).get_runtime_state() is None


def test_the_recorded_runtime_row_reads_back(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    _upsert(store, "session-a")

    state = store.get_runtime_state()

    assert state is not None
    assert state["session_id"] == "session-a"
    assert state["daemon_host"] == "127.0.0.1"
    assert state["daemon_port"] == 4319
    assert state["started_at"] == "2026-11-22T00:00:00+00:00"
    assert state["last_heartbeat_at"] == "2026-11-22T00:00:05+00:00"


def test_clearing_another_session_keeps_the_row(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    _upsert(store, "session-new")

    store.clear_runtime_state(session_id="session-old")
    state = store.get_runtime_state()
    assert state is not None
    assert state["session_id"] == "session-new"

    store.clear_runtime_state(session_id="session-new")
    assert store.get_runtime_state() is None


def test_a_damaged_port_is_refused(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    _upsert(store, "session-a")
    with sqlite3.connect(store.path) as connection:
        connection.execute("update guard_runtime_state set daemon_port = 'not-a-port'")

    with pytest.raises(ValueError, match="invalid runtime state row"):
        store.get_runtime_state()


@pytest.mark.parametrize(
    "answer",
    [
        [],
        {"session_id": "s"},
        {
            "session_id": "s",
            "daemon_host": "h",
            "daemon_port": True,
            "started_at": "a",
            "last_heartbeat_at": "b",
        },
        {
            "session_id": "s",
            "daemon_host": "h",
            "daemon_port": "4319",
            "started_at": "a",
            "last_heartbeat_at": "b",
        },
        {
            "session_id": None,
            "daemon_host": "h",
            "daemon_port": 1,
            "started_at": "a",
            "last_heartbeat_at": "b",
        },
        {
            "session_id": "s",
            "daemon_host": "h",
            "daemon_port": 1,
            "started_at": "a",
            "last_heartbeat_at": "b",
            "extra": 1,
        },
    ],
)
def test_a_malformed_native_answer_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    store = GuardStore(tmp_path)

    def fake_call(method: str, args: dict[str, Any]) -> object:
        assert method == "get_runtime_state"
        assert args == {}
        return answer

    monkeypatch.setattr(store, "_native_store_call", fake_call)

    with pytest.raises(RuntimeError, match="native get_runtime_state returned no answer"):
        store.get_runtime_state()
