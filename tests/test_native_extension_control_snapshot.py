"""The committed extension-control snapshot answers from the native store."""

from __future__ import annotations

import sqlite3

import pytest

from codex_plugin_scanner.guard.native_extension_control_snapshot import extension_control_snapshot_layers
from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityError


class _Store:
    def __init__(self, snapshot_answer: object, schema_state: str = "compatible") -> None:
        self.answers = {
            "extension_control_schema_state": {"state": schema_state},
            "extension_control_snapshot_layers": snapshot_answer,
        }
        self.calls: list[str] = []

    def _native_store_call(self, method: str, args: dict[str, object]) -> object:
        assert args == {}
        self.calls.append(method)
        return self.answers[method]

    def _connect(self) -> object:
        raise AssertionError("the snapshot read must not open a connection")


def test_a_missing_snapshot_reads_as_absent_after_the_schema_check() -> None:
    store = _Store({"snapshot": None})

    snapshot = extension_control_snapshot_layers(store)

    assert not snapshot.present
    assert snapshot.layers_json is None
    assert store.calls == ["extension_control_schema_state", "extension_control_snapshot_layers"]


def test_a_committed_snapshot_returns_its_layers() -> None:
    store = _Store({"snapshot": {"layers_json": "[]"}})

    snapshot = extension_control_snapshot_layers(store)

    assert snapshot.present
    assert snapshot.layers_json == "[]"


def test_a_snapshot_with_unreadable_layers_is_still_present() -> None:
    snapshot = extension_control_snapshot_layers(_Store({"snapshot": {"layers_json": None}}))

    assert snapshot.present
    assert snapshot.layers_json is None


def test_an_unknown_schema_marker_stops_before_the_snapshot_read() -> None:
    store = _Store({"snapshot": None}, schema_state="incompatible")

    with pytest.raises(ExtensionControlAuthorityError):
        extension_control_snapshot_layers(store)
    assert store.calls == ["extension_control_schema_state"]


@pytest.mark.parametrize(
    "answer",
    [
        None,
        [],
        {},
        {"snapshot": None, "extra": 1},
        {"snapshot": []},
        {"snapshot": {}},
        {"snapshot": {"layers_json": 3}},
        {"snapshot": {"layers_json": "[]", "revision": 1}},
    ],
)
def test_a_malformed_answer_fails_closed(answer: object) -> None:
    with pytest.raises(sqlite3.DatabaseError, match="extension_control_snapshot_layers"):
        extension_control_snapshot_layers(_Store(answer))
