"""Parity of the native `guard_store` op against vectors recorded from origin/main Python.

The vectors (schema, seed rows, results, post-step state) were produced by the
original Python `GuardStore` implementation, never by Rust. These tests check
that (1) the Python wrappers translate every recorded call to the recorded wire
arguments, (2) the database schema written by origin/main is the schema the
current store writes, and (3) a database written by origin/main is readable and
writable through the real resident op with the recorded results.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import store_review_event_outbox
from codex_plugin_scanner.guard.store import GuardStore

# pyright: reportAny=false, reportPrivateUsage=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false

VECTORS_PATH = Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/testdata/guard_store/vectors.json"
VECTORS: dict[str, Any] = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
FROZEN_NOW = VECTORS["frozen_now"]
OUTBOX_TABLES = (
    "guard_review_outbox_cursors",
    "guard_review_outbox_events",
    "guard_review_outbox_request_sequences",
    "guard_review_outbox_wake_state",
)
# Scenarios whose steps append events draw uuid4 ids the recorder froze; the
# end-to-end replay through the real resident only covers id-free scenarios.
UUID_FREE = {"empty", "bound_lifecycle", "unbound_then_bound", "unbound_refresh", "rebinding_quarantine"}


def _invoke(store: GuardStore, method: str, kwargs: dict[str, Any]) -> object:
    call = dict(kwargs)
    if method in {"acknowledge_review_events", "retry_review_events"}:
        return getattr(store, method)(call.pop("sequences"), **call)
    if method == "quarantine_review_event":
        return store.quarantine_review_event(call.pop("sequence"), **call)
    if method == "refresh_review_event_outbox_binding_for_identity":
        return store.refresh_review_event_outbox_binding_for_identity(call.pop("workspace_id"), **call)
    if method == "list_review_event_snapshots":
        return store.list_review_event_snapshots(call["request_id"])
    if call.get("request_ids") is not None:
        call["request_ids"] = set(call["request_ids"])
    if method == "recover_review_snapshot_sequences":
        call["collisions"] = {int(sequence): event_id for sequence, event_id in call["collisions"].items()}
    return getattr(store, method)(**call)


def _native_shape(method: str, value: object) -> object:
    if method == "recover_review_snapshot_sequences":
        assert isinstance(value, dict)
        return [[old, new] for old, new in sorted(value.items())]
    return value


def _steps() -> list[tuple[str, int, dict[str, Any]]]:
    return [
        (scenario["name"], index, step)
        for scenario in VECTORS["scenarios"]
        for index, step in enumerate(scenario["steps"])
        if step["error"] is None
    ]


@pytest.mark.parametrize(("name", "index", "step"), _steps(), ids=lambda value: str(value)[:24])
def test_wrappers_send_the_recorded_wire_arguments(
    name: str,
    index: int,
    step: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home", source=VECTORS["source"])
    captured: list[tuple[str, object]] = []

    def capture(**kwargs: Any) -> tuple[object, None]:
        captured.append((kwargs["method"], json.loads(json.dumps(kwargs["args"]))))
        return step["result"], None

    monkeypatch.setattr(store_review_event_outbox, "native_guard_store_call", capture)
    monkeypatch.setattr(store_review_event_outbox, "_now", lambda: FROZEN_NOW)
    _ = _invoke(store, step["method"], step["kwargs"])
    assert captured == [(step["method"], step["wire_args"])], f"{name}#{index}"


def _schema_sql(path: Path) -> list[str]:
    connection = sqlite3.connect(path)
    try:
        return [
            row[0]
            for row in connection.execute(
                "select sql from sqlite_master where sql is not null and name not like 'sqlite_%' "
                "order by case type when 'table' then 0 when 'index' then 1 else 2 end, rowid"
            )
        ]
    finally:
        connection.close()


def test_origin_main_schema_equals_current_store_schema(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", source=VECTORS["source"])
    assert _schema_sql(Path(store.path)) == VECTORS["schema_sql"]


def _rows(path: Path, table: str) -> list[dict[str, object]]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in connection.execute(f"select * from {table} order by rowid")]
    finally:
        connection.close()


def _write_origin_main_database(path: Path, scenario: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        for statement in VECTORS["schema_sql"]:
            connection.execute(statement)
        for table, rows in scenario["seed"].items():
            connection.execute(f"delete from {table}")
            for row in rows:
                columns = ",".join(row)
                marks = ",".join("?" for _ in row)
                connection.execute(f"insert into {table} ({columns}) values ({marks})", list(row.values()))
        connection.commit()
    finally:
        connection.close()


@pytest.mark.parametrize(
    "scenario", [s for s in VECTORS["scenarios"] if s["name"] in UUID_FREE], ids=lambda s: s["name"]
)
def test_database_written_by_origin_main_replays_through_the_resident(
    scenario: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "guard-home"
    _write_origin_main_database(home / "guard.db", scenario)
    store = GuardStore(home, source=VECTORS["source"])
    monkeypatch.setattr(store_review_event_outbox, "_now", lambda: FROZEN_NOW)
    expected: dict[str, list[dict[str, object]]] = dict(scenario["seed"])
    for index, step in enumerate(scenario["steps"]):
        label = f"{scenario['name']}#{index} {step['method']}"
        if step["error"] is not None:
            with pytest.raises((ValueError, sqlite3.IntegrityError)) as raised:
                _invoke(store, step["method"], step["kwargs"])
            assert type(raised.value).__name__ == step["error"]["type"], label
            assert str(raised.value) == step["error"]["message"], label
        else:
            result = _invoke(store, step["method"], step["kwargs"])
            assert json.loads(json.dumps(_native_shape(step["method"], result))) == step["result"], label
        expected.update(step["post_changed"])
        for table in OUTBOX_TABLES:
            assert _rows(Path(store.path), table) == expected[table], f"{label}: {table}"
