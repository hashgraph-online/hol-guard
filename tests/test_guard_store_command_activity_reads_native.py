"""Command-activity health, the activity count and the table names are read by the native store."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.native_guard_store import NativeGuardStoreUnavailable
from codex_plugin_scanner.guard.store import GuardStore


def _unavailable(reason: str) -> NativeGuardStoreUnavailable:
    error = NativeGuardStoreUnavailable(f"unavailable ({reason})")
    error.reason = reason
    return error


def test_a_fresh_store_reads_healthy_counters_and_no_activities(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)

    health = store.get_command_activity_persistence_health()

    assert health.dropped_event_count == 0
    assert health.persistence_error_count == 0
    assert health.active_error_count == 0
    assert health.last_error_code is None
    assert health.last_error_at is None
    assert health.schema_version
    assert store.count_command_activities() == 0


def test_table_names_read_sorted(tmp_path: Path) -> None:
    names = GuardStore(tmp_path).list_table_names()

    assert names == sorted(names)
    assert {"command_activity", "command_activity_health", "guard_events"} <= set(names)


def test_a_recorded_failure_reads_back_through_the_health(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    occurred_at = datetime(2026, 11, 22, tzinfo=timezone.utc)
    store.record_command_activity_persistence_failure(error_code="disk_full", occurred_at=occurred_at)

    health = store.get_command_activity_persistence_health()

    assert health.dropped_event_count == 1
    assert health.persistence_error_count == 1
    assert health.last_error_code == "disk_full"
    assert health.last_error_at == occurred_at


_HEALTH = {
    "dropped_event_count": 0,
    "persistence_error_count": 0,
    "active_error_count": 0,
    "last_error_code": None,
    "last_error_at": None,
    "schema_version": "11",
}


@pytest.mark.parametrize(
    "answer",
    [
        None,
        [],
        {key: value for key, value in _HEALTH.items() if key != "schema_version"},
        {**_HEALTH, "extra": 1},
        {**_HEALTH, "dropped_event_count": True},
        {**_HEALTH, "active_error_count": "1"},
        {**_HEALTH, "last_error_code": 7},
        {**_HEALTH, "schema_version": None},
    ],
)
def test_a_malformed_health_answer_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    store = GuardStore(tmp_path)

    def native(method: str, _args: object, **_kwargs: Any) -> object:
        assert method == "get_command_activity_persistence_health"
        return answer

    monkeypatch.setattr(store, "_native_store_call", native)

    with pytest.raises(RuntimeError, match="returned no answer"):
        store.get_command_activity_persistence_health()


@pytest.mark.parametrize("table", ["command_activity_health", "command_activity_health_active"])
def test_missing_health_rows_read_as_unavailable(tmp_path: Path, table: str) -> None:
    store = GuardStore(tmp_path)
    store.get_command_activity_persistence_health()
    with sqlite3.connect(store.path) as connection:
        connection.execute(f"delete from {table}")

    with pytest.raises(RuntimeError, match="command activity persistence health is unavailable"):
        store.get_command_activity_persistence_health()


def test_an_unavailable_runtime_is_not_reported_as_missing_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path)

    def native(_method: str, _args: object, **_kwargs: Any) -> object:
        raise _unavailable("native_guard_store_unavailable")

    monkeypatch.setattr(store, "_native_store_call", native)

    with pytest.raises(NativeGuardStoreUnavailable):
        store.get_command_activity_persistence_health()


@pytest.mark.parametrize("answer", [None, -1, True, "3", 1.0])
def test_a_malformed_count_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    store = GuardStore(tmp_path)

    def native(method: str, _args: object, **_kwargs: Any) -> object:
        assert method == "count_command_activities"
        return answer

    monkeypatch.setattr(store, "_native_store_call", native)

    with pytest.raises(RuntimeError, match="native count_command_activities returned no answer"):
        store.count_command_activities()


@pytest.mark.parametrize("answer", [None, {}, ["a", 1]])
def test_malformed_table_names_are_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    store = GuardStore(tmp_path)

    def native(method: str, _args: object, **_kwargs: Any) -> object:
        assert method == "list_table_names"
        return answer

    monkeypatch.setattr(store, "_native_store_call", native)

    with pytest.raises(RuntimeError, match="native list_table_names returned no answer"):
        store.list_table_names()
