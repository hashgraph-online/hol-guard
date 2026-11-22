"""The connected Cloud workspace id comes from the native store and is checked."""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.store_inventory import StoreInventoryMixin


def _read(answer: object) -> str | None:
    calls: list[tuple[str, dict[str, object]]] = []

    def native_store_call(method: str, args: dict[str, object]) -> object:
        calls.append((method, args))
        return answer

    store = SimpleNamespace(_native_store_call=native_store_call)
    result = StoreInventoryMixin.get_cloud_workspace_id(cast(StoreInventoryMixin, cast(object, store)))
    assert calls == [("cloud_workspace_id", {})]
    return result


def test_the_native_answer_names_the_workspace() -> None:
    assert _read({"state": "present", "workspace_id": "workspace-1"}) == "workspace-1"


def test_no_record_is_no_workspace() -> None:
    assert _read({"state": "present", "workspace_id": None}) is None


def test_a_malformed_record_raises_value_error() -> None:
    with pytest.raises(ValueError):
        _ = _read({"state": "malformed"})


@pytest.mark.parametrize(
    "answer",
    [
        None,
        [],
        {"state": "present"},
        {"state": "present", "workspace_id": 7},
        {"state": "other", "workspace_id": "w"},
        {"state": "present", "workspace_id": "w", "extra": 1},
    ],
)
def test_an_answer_outside_the_contract_is_refused(answer: object) -> None:
    with pytest.raises(sqlite3.DatabaseError):
        _ = _read(answer)
