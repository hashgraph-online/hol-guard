"""Parity of the native command-activity store methods against recorded vectors.

The vectors were produced by the original Python store mixins (never by Rust).
These tests check that (1) the Python wrappers translate every recorded call to
the recorded wire arguments, (2) the command-activity schema the store creates
is the schema the original wrote, and (3) every recorded call replays through
the real resident with the recorded result, error and post-step table state.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_guard_store, store_review_event_outbox
from codex_plugin_scanner.guard.runtime.command_activity_contract import CommandActivity
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_command_activity_maintenance import CommandActivityMaintenanceResult
from codex_plugin_scanner.guard.store_command_activity_wire import activity_wire

# pyright: reportAny=false, reportPrivateUsage=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false

DATA_DIR = Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/testdata/guard_store"
VECTORS: dict[str, Any] = json.loads((DATA_DIR / "command_activity_vectors.json").read_text(encoding="utf-8"))
sys.path.insert(0, str(DATA_DIR))
from command_activity_scenarios import SCENARIOS  # noqa: E402

ERROR_CODES = {
    "ValueError": "native_guard_store_value_error",
    "RuntimeError": "native_guard_store_runtime_error",
    "IntegrityError": "native_guard_store_integrity_error",
}
NATIVE_METHOD = {"get_command_activity_by_request_correlation": "command_activity_by_request_correlation"}
SCENARIO_STEPS = {scenario["name"]: scenario["steps"] for scenario in SCENARIOS}


def _cases() -> list[tuple[str, int, dict[str, Any], dict[str, Any]]]:
    return [
        (scenario["name"], index, source, step)
        for scenario in VECTORS["scenarios"]
        for index, (source, step) in enumerate(zip(SCENARIO_STEPS[scenario["name"]], scenario["steps"], strict=True))
        if "sql" not in source
    ]


def _invoke(store: GuardStore, source: dict[str, Any]) -> object:
    return getattr(store, source["method"])(*source.get("args", ()), **source.get("kwargs", {}))


def _json(value: object) -> object:
    if isinstance(value, CommandActivity):
        return activity_wire(value)
    if isinstance(value, CommandActivityMaintenanceResult):
        return [
            value.ran,
            value.completed,
            value.backfilled_rows,
            value.detail_rows_deleted,
            value.correlation_rows_deleted,
            value.aggregate_rows_deleted,
        ]
    return value


def test_every_scenario_has_matching_recorded_steps() -> None:
    assert len(VECTORS["scenarios"]) >= 8
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
        return step["result"], None

    monkeypatch.setattr(store_review_event_outbox, "native_guard_store_call", capture)
    label = f"{name}#{index}"
    if step["python_side"]:
        with pytest.raises(ValueError) as raised:
            _invoke(store, source)
        assert str(raised.value) == step["error"]["message"], label
        assert captured == [], label
        return
    if step["error"] is not None:
        with pytest.raises((ValueError, RuntimeError, sqlite3.IntegrityError)) as raised:
            _invoke(store, source)
        assert type(raised.value).__name__ == step["error"]["type"], label
        assert str(raised.value) == step["error"]["message"], label
    else:
        assert json.loads(json.dumps(_json(_invoke(store, source)))) == step["result"], label
    if not captured:
        # Rejected without a resident call: only a request-less pre replay.
        assert step["method"] == "is_exact_command_activity_pre_replay" and step["result"] is False, label
        return
    assert captured == [(NATIVE_METHOD.get(step["method"], step["method"]), step["wire_args"])], label


def _schema_sql(path: Path) -> list[str]:
    connection = sqlite3.connect(path)
    try:
        return [
            row[0]
            for row in connection.execute(
                "select sql from sqlite_master where sql is not null and tbl_name like 'command_activity%' "
                "order by case type when 'table' then 0 when 'index' then 1 else 2 end, rowid"
            )
        ]
    finally:
        connection.close()


def test_recorded_schema_equals_current_store_schema(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    assert _schema_sql(Path(store.path)) == VECTORS["schema_sql"]


def _dump(path: Path) -> dict[str, list[dict[str, object]]]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return {
            table: [dict(row) for row in connection.execute(f"select * from {table} order by {key}")]
            for table, key in VECTORS["order_by"].items()
        }
    finally:
        connection.close()


@pytest.mark.parametrize("scenario", VECTORS["scenarios"], ids=lambda scenario: scenario["name"])
def test_recorded_scenarios_replay_through_the_resident(scenario: dict[str, Any], tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    path = Path(store.path)
    expected = _dump(path)
    assert expected == scenario["seed"]
    for index, (source, step) in enumerate(zip(SCENARIO_STEPS[scenario["name"]], scenario["steps"], strict=True)):
        label = f"{scenario['name']}#{index} {step['method']}"
        if "sql" in source:
            with sqlite3.connect(path) as connection:
                for statement, params in source["sql"]:
                    connection.execute(statement, params)
        elif step["error"] is not None:
            with pytest.raises((ValueError, RuntimeError, sqlite3.IntegrityError)) as raised:
                _invoke(store, source)
            assert type(raised.value).__name__ == step["error"]["type"], label
            assert str(raised.value) == step["error"]["message"], label
        else:
            assert json.loads(json.dumps(_json(_invoke(store, source)))) == step["result"], label
        expected.update(step["post_changed"])
        assert _dump(path) == expected, label
