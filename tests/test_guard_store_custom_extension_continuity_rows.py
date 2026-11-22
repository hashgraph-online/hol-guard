"""The native store reads the custom Extension continuity inputs in one snapshot."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import custom_extension_continuity
from codex_plugin_scanner.guard.runtime.custom_extension_continuity import (
    CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY,
    CUSTOM_EXTENSION_CONTINUITY_STATE_KEY,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_custom_extension_continuity_rows import (
    CustomExtensionContinuityRows,
    CustomExtensionContinuityRowUnreadableError,
)

_NOW = "2026-11-22T00:00:00+00:00"


def test_an_empty_store_holds_revision_zero_and_no_rows(tmp_path: Path) -> None:
    assert GuardStore(tmp_path).custom_extension_continuity_rows() == CustomExtensionContinuityRows(0, None, None)


def test_stored_rows_come_back_with_the_revision(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(CUSTOM_EXTENSION_CONTINUITY_STATE_KEY, {"items": {"cli-a": {"status": "applied"}}}, _NOW)
    store.set_sync_payload(CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY, {"cli-b": {"removed_at": _NOW}}, _NOW)

    rows = store.custom_extension_continuity_rows()

    assert rows.revision == store.read_local_cli_revision()
    assert rows.state == {"items": {"cli-a": {"status": "applied"}}}
    assert rows.removals == {"cli-b": {"removed_at": _NOW}}


@pytest.mark.parametrize("key", [CUSTOM_EXTENSION_CONTINUITY_STATE_KEY, CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY])
def test_a_row_that_is_not_json_refuses_the_snapshot(tmp_path: Path, key: str) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(key, {"items": {}}, _NOW)
    with sqlite3.connect(store.path) as connection:
        connection.execute("update sync_state set payload_json = 'not-json' where state_key = ?", (key,))

    with pytest.raises(CustomExtensionContinuityRowUnreadableError, match="custom_extension_continuity_unreadable"):
        store.custom_extension_continuity_rows()


def test_public_state_survives_a_damaged_removals_row(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(CUSTOM_EXTENSION_CONTINUITY_STATE_KEY, {"items": {"cli-a": {}}}, _NOW)
    store.set_sync_payload(CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY, {"cli-b": {}}, _NOW)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update sync_state set payload_json = 'not-json' where state_key = ?",
            (CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY,),
        )
    seen: list[dict[str, object]] = []

    def answer(_store: GuardStore, request: dict[str, object], _keys: frozenset[str]) -> dict[str, object]:
        seen.append(request)
        return {"states": {"cli-a": {"status": "applied"}}}

    monkeypatch.setattr(custom_extension_continuity, "_native_continuity", answer)

    states = custom_extension_continuity.continuity_state_for_local_items(store, now=_NOW)

    assert states == {"cli-a": {"status": "applied"}}
    assert seen[0]["stored"] == {"items": {"cli-a": {}}}


def test_an_answer_without_a_whole_revision_is_refused() -> None:
    with pytest.raises(RuntimeError, match="no answer"):
        CustomExtensionContinuityRows.from_native(
            {"revision": True, "state_json": None, "removals_json": None, "unreadable": []}
        )


@pytest.mark.parametrize("text", ["7", "not json", 7])
def test_a_row_text_that_is_not_an_object_or_array_is_refused(text: object) -> None:
    with pytest.raises(RuntimeError, match="no answer"):
        CustomExtensionContinuityRows.from_native(
            {"revision": 0, "state_json": text, "removals_json": None, "unreadable": []}
        )


def test_stored_item_order_comes_back_unchanged(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(
        CUSTOM_EXTENSION_CONTINUITY_STATE_KEY, {"items": {"cli-b": {}, "cli-a": {}, "cli-c": {}}}, _NOW
    )

    state = store.custom_extension_continuity_rows().state

    assert isinstance(state, dict)
    items = state["items"]
    assert isinstance(items, dict)
    assert list(items) == ["cli-b", "cli-a", "cli-c"]
