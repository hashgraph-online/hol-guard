"""Parity of the native command-activity read, feedback and privacy methods.

The vectors were produced by the original Python store mixins (never by Rust).
These tests check that (1) the Python wrappers translate every recorded call to
the recorded wire arguments and rebuild the recorded result from the resident
payload, and (2) every recorded call replays through the real resident with the
recorded result, error and post-step table state.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import store_review_event_outbox
from codex_plugin_scanner.guard.native_guard_store import _raise_for_code
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_command_activity_wire import shadow_wire

# pyright: reportAny=false, reportPrivateUsage=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false

DATA_DIR = Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/testdata/guard_store"
VECTORS: dict[str, Any] = json.loads((DATA_DIR / "command_activity_read_vectors.json").read_text(encoding="utf-8"))
sys.path.insert(0, str(DATA_DIR))
from command_activity_read_scenarios import SCENARIOS, seed_statements  # noqa: E402

ERROR_CODES = {
    "ValueError": "native_guard_store_value_error",
    "RuntimeError": "native_guard_store_runtime_error",
    "IntegrityError": "native_guard_store_integrity_error",
}
SCENARIO_STEPS = {scenario["name"]: scenario["steps"] for scenario in SCENARIOS}
SCENARIO_SEED = {scenario["name"]: scenario["seed"] for scenario in SCENARIOS}
NOT_FOUND = "CommandActivityNotFoundError"


def _cases() -> list[tuple[str, int, dict[str, Any], dict[str, Any]]]:
    return [
        (scenario["name"], index, source, step)
        for scenario in VECTORS["scenarios"]
        for index, (source, step) in enumerate(zip(SCENARIO_STEPS[scenario["name"]], scenario["steps"], strict=True))
        if "sql" not in source
    ]


def _invoke(store: GuardStore, source: dict[str, Any]) -> object:
    return getattr(store, source["method"])(*source.get("args", ()), **source.get("kwargs", {}))


def _json(method: str, value: object) -> object:
    if method == "list_command_shadow_observations":
        return [shadow_wire(item) for item in value]  # type: ignore[attr-defined]
    return json.loads(json.dumps(value, default=list))


def _seed(path: Path, name: str) -> None:
    if not SCENARIO_SEED[name]:
        return
    with sqlite3.connect(path) as connection:
        for statement, params in seed_statements():
            connection.execute(statement, params)


def test_every_scenario_has_matching_recorded_steps() -> None:
    assert len(VECTORS["scenarios"]) >= 5
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
        error = step["error"]
        if error is not None and error["type"] == NOT_FOUND:
            return {"not_found": True}, None
        if error is not None:
            _raise_for_code(ERROR_CODES[error["type"]], {"message": error["message"]})
        return step["native_payload"], None

    monkeypatch.setattr(store_review_event_outbox, "native_guard_store_call", capture)
    label = f"{name}#{index} {step['label']}"
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
        assert _json(step["method"], _invoke(store, source)) == step["result"], label
    assert captured == [(step["method"], step["wire_args"])], label


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
    _seed(path, scenario["name"])
    expected = _dump(path)
    assert expected == scenario["seed"]
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
            assert str(raised.value) == step["error"]["message"], label
        else:
            assert _json(step["method"], _invoke(store, source)) == step["result"], label
        expected.update(step["post_changed"])
        assert _dump(path) == expected, label
