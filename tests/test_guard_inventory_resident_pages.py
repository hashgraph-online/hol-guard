"""Inventory list wrappers follow resident pages and fail closed."""

from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.guard.store_inventory import StoreInventoryMixin


class _Pages(StoreInventoryMixin):
    def __init__(self, pages: list[object]) -> None:
        self.pages = list(pages)
        self.calls: list[tuple[str, dict[str, object]]] = []

    def _native_store_call(self, method: str, args: dict[str, object]) -> object:
        self.calls.append((method, dict(args)))
        if not self.pages:
            raise RuntimeError("native_guard_store_unavailable")
        page = self.pages.pop(0)
        if isinstance(page, Exception):
            raise page
        return page


def test_list_inventory_assembles_every_resident_page() -> None:
    store = _Pages(
        [
            {"rows": [{"artifact_id": "a"}], "next": {"artifact_id": "a", "artifact_name": "n"}},
            {"rows": [{"artifact_id": "b"}], "next": None},
        ]
    )

    assert store.list_inventory("codex") == [{"artifact_id": "a"}, {"artifact_id": "b"}]
    assert store.calls[0][0] == "list_artifact_inventory"
    assert "after" not in store.calls[0][1]
    assert store.calls[1][1]["after"] == {"artifact_id": "a", "artifact_name": "n"}
    assert store.calls[1][1]["harness"] == "codex"


def test_list_snapshots_assembles_pages_into_the_caller_dict() -> None:
    store = _Pages(
        [
            {
                "rows": [{"artifact_id": "a", "snapshot_json": json.dumps({"n": 1})}],
                "next": {"artifact_id": "a"},
            },
            {
                "rows": [{"artifact_id": "b", "snapshot_json": json.dumps({"n": 2})}],
                "next": None,
            },
        ]
    )

    assert store.list_snapshots("codex") == {"a": {"n": 1}, "b": {"n": 2}}
    assert [call[0] for call in store.calls] == ["list_artifact_snapshots", "list_artifact_snapshots"]


def test_resident_failure_does_not_return_a_partial_inventory() -> None:
    store = _Pages(
        [
            {"rows": [{"artifact_id": "a"}], "next": {"artifact_id": "a", "artifact_name": "n"}},
            RuntimeError("native_guard_store_unavailable"),
        ]
    )

    with pytest.raises(RuntimeError, match="native_guard_store_unavailable"):
        store.list_inventory()
    assert len(store.calls) == 2


def test_stalled_inventory_cursor_is_not_a_complete_list() -> None:
    cursor = {"artifact_id": "a", "artifact_name": "n"}
    store = _Pages([{"rows": [{"artifact_id": "a"}], "next": cursor}, {"rows": [], "next": cursor}])

    with pytest.raises(ValueError, match="native_inventory_page_stalled"):
        store.list_inventory("codex")
