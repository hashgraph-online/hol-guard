"""Parity of the native artifact snapshot, diff, inventory, capability and provenance store methods.

The vectors were produced by the original Python store mixin (never by Rust).
These tests check that (1) the Python wrappers translate every recorded call to
the recorded wire arguments and shape the recorded raw rows into the recorded
results, (2) the tables the store creates are the tables the original wrote,
and (3) every recorded call replays through the real resident with the
recorded result, error and post-step table state.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_guard_store, store_review_event_outbox
from codex_plugin_scanner.guard.store import GuardStore

# pyright: reportAny=false, reportPrivateUsage=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false

DATA_DIR = Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/testdata/guard_store"
VECTORS: dict[str, Any] = json.loads((DATA_DIR / "inventory_vectors.json").read_text(encoding="utf-8"))
sys.path.insert(0, str(DATA_DIR))
from inventory_scenarios import SCENARIOS, jsonable  # noqa: E402

ERROR_CODES = {
    "ValueError": "native_guard_store_value_error",
    "RuntimeError": "native_guard_store_runtime_error",
    "IntegrityError": "native_guard_store_integrity_error",
}
SCENARIO_STEPS = {scenario["name"]: scenario["steps"] for scenario in SCENARIOS}
JSON_SUFFIX = "_json"


def _cases() -> list[tuple[str, int, dict[str, Any], dict[str, Any]]]:
    return [
        (scenario["name"], index, source, step)
        for scenario in VECTORS["scenarios"]
        for index, (source, step) in enumerate(zip(SCENARIO_STEPS[scenario["name"]], scenario["steps"], strict=True))
        if "sql" not in source
    ]


def _invoke(store: GuardStore, source: dict[str, Any]) -> object:
    return getattr(store, source["method"])(*source.get("args", ()), **source.get("kwargs", {}))


def test_every_scenario_has_matching_recorded_steps() -> None:
    assert len(VECTORS["scenarios"]) >= 7
    for scenario in VECTORS["scenarios"]:
        assert len(scenario["steps"]) == len(SCENARIO_STEPS[scenario["name"]])


@pytest.mark.parametrize(("name", "index", "source", "step"), _cases(), ids=lambda value: str(value)[:24])
def test_wrappers_send_the_recorded_wire_arguments(
    name: str,
    index: int,
    source: dict[str, Any],
    step: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    captured: list[tuple[str, object]] = []

    def capture(**kwargs: Any) -> tuple[object, None]:
        captured.append((kwargs["method"], json.loads(json.dumps(kwargs["args"]))))
        if step["error"] is not None:
            native_guard_store._raise_for_code(
                ERROR_CODES[step["error"]["type"]], {"message": step["error"]["message"]}
            )
        return step["native_payload"], None

    monkeypatch.setattr(store_review_event_outbox, "native_guard_store_call", capture)
    label = f"{name}#{index} {step['label']}"
    if step["error"] is not None:
        with pytest.raises((ValueError, RuntimeError, sqlite3.IntegrityError)) as raised:
            _invoke(store, source)
        assert type(raised.value).__name__ == step["error"]["type"], label
        assert str(raised.value) == step["error"]["message"], label
    else:
        assert json.loads(json.dumps(jsonable(_invoke(store, source)))) == step["result"], label
    assert captured == [(step["method"], step["wire_args"])], label


def _schema_sql(path: Path) -> list[str]:
    connection = sqlite3.connect(path)
    try:
        return [
            row[0]
            for row in connection.execute(
                "select sql from sqlite_master where sql is not null "
                f"and tbl_name in ({','.join('?' * len(VECTORS['order_by']))}) "
                "order by case type when 'table' then 0 when 'index' then 1 else 2 end, rowid",
                tuple(VECTORS["order_by"]),
            )
        ]
    finally:
        connection.close()


def test_recorded_schema_equals_current_store_schema(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    assert _schema_sql(Path(store.path)) == VECTORS["schema_sql"]


def _decode(key: str, value: object) -> object:
    if not key.endswith(JSON_SUFFIX) or not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except ValueError:
        return value


def _decoded(row: dict[str, object]) -> dict[str, object]:
    # The resident re-serializes merged metadata compactly; compare decoded values.
    return {key: _decode(key, value) for key, value in row.items()}


def _where(table: str) -> str:
    return f" where {VECTORS['where'][table]}" if table in VECTORS["where"] else ""


def _dump(path: Path) -> dict[str, list[dict[str, object]]]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return {
            table: [
                _decoded(dict(row))
                for row in connection.execute(f"select * from {table}{_where(table)} order by {key}")
            ]
            for table, key in VECTORS["order_by"].items()
        }
    finally:
        connection.close()


@pytest.mark.parametrize("scenario", VECTORS["scenarios"], ids=lambda scenario: scenario["name"])
def test_recorded_scenarios_replay_through_the_resident(
    scenario: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    path = Path(store.path)
    expected = _dump(path)
    assert expected == {table: [_decoded(row) for row in rows] for table, rows in scenario["seed"].items()}
    for index, (source, step) in enumerate(zip(SCENARIO_STEPS[scenario["name"]], scenario["steps"], strict=True)):
        label = f"{scenario['name']}#{index} {step['label']}"
        if "sql" in source:
            with sqlite3.connect(path) as connection:
                for statement, params in source["sql"]:
                    connection.execute(statement, params)
        elif step["error"] is not None:
            with pytest.raises((ValueError, RuntimeError, sqlite3.IntegrityError)) as raised:
                _invoke(store, source)
            assert type(raised.value).__name__ == step["error"]["type"], label
            if step["error"]["message_exact"]:
                assert str(raised.value) == step["error"]["message"], label
        else:
            assert json.loads(json.dumps(jsonable(_invoke(store, source)))) == step["result"], label
        expected.update({table: [_decoded(row) for row in rows] for table, rows in step["post_changed"].items()})
        assert _dump(path) == expected, label
