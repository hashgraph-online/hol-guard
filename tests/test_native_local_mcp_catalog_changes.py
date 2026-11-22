"""The catalog change names a grant reviews, read by the native store."""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from codex_plugin_scanner.guard import store_mcp_catalog
from codex_plugin_scanner.guard.store_mcp_catalog import catalog_change_ids


class _Store:
    def __init__(self, answer: object) -> None:
        self.answer = answer
        self.calls: list[tuple[str, dict[str, object]]] = []

    def _native_store_call(self, method: str, args: dict[str, object]) -> Any:
        self.calls.append((method, args))
        return self.answer


def _slugs(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    seen: list[list[str]] = []

    def slug(names: list[str]) -> tuple[str, ...]:
        seen.append(list(names))
        return tuple(f"id-{name}" for name in names)

    monkeypatch.setattr(store_mcp_catalog, "slug_local_cli_command_ids", slug)
    return seen


def test_no_cli_ids_reads_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _slugs(monkeypatch)
    store = _Store({"names": ["a"]})
    assert catalog_change_ids(store, ()) == {}
    assert catalog_change_ids(store, {}) == {}
    assert store.calls == []
    assert seen == []


def test_the_native_names_become_command_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _slugs(monkeypatch)
    store = _Store({"names": ["beta", "alpha"]})
    assert catalog_change_ids(store, {"cli-a": 3, "cli-b": 4}) == {"alpha": "id-alpha", "beta": "id-beta"}
    assert store.calls == [("local_mcp_catalog_change_names", {"cli_ids": ["cli-a", "cli-b"]})]
    assert seen == [["alpha", "beta"]]


def test_no_flagged_names_skips_the_slug_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _slugs(monkeypatch)
    assert catalog_change_ids(_Store({"names": []}), ("cli-a",)) == {}
    assert seen == []


def test_unavailable_slugs_leave_the_changes_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(names: list[str]) -> tuple[str, ...]:
        raise ValueError("command ids are unavailable")

    monkeypatch.setattr(store_mcp_catalog, "slug_local_cli_command_ids", unavailable)
    assert catalog_change_ids(_Store({"names": ["a"]}), ("cli-a",)) == {}


@pytest.mark.parametrize("answer", [None, [], {"names": None}, {"names": ["a", 1]}, {"other": []}])
def test_an_answer_outside_the_contract_is_refused(answer: object, monkeypatch: pytest.MonkeyPatch) -> None:
    _slugs(monkeypatch)
    with pytest.raises(sqlite3.DatabaseError, match="local_mcp_catalog_change_names"):
        catalog_change_ids(_Store(answer), ("cli-a",))
