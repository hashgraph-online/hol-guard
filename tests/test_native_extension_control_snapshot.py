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


def test_an_open_connection_scope_reads_the_snapshot_on_the_shared_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard import native_extension_control_schema, native_extension_control_snapshot

    connection = sqlite3.connect(":memory:")
    connection.execute("create table extension_control_authority_snapshot (singleton integer, layers_json)")

    class _ScopedStore(_Store):
        def _connect(self) -> sqlite3.Connection:
            return connection

    monkeypatch.setattr(native_extension_control_schema, "owns_scope", lambda _store: True)
    monkeypatch.setattr(native_extension_control_snapshot, "owns_scope", lambda _store: True)
    monkeypatch.setattr(
        native_extension_control_schema,
        "require_compatible_extension_control_schema",
        lambda _connection, *, require_compatible: True,
    )
    store = _ScopedStore(None)

    missing = extension_control_snapshot_layers(store)
    assert (missing.present, missing.layers_json) == (False, None)
    connection.execute("insert into extension_control_authority_snapshot values (1, ?)", (b"[]",))
    unreadable = extension_control_snapshot_layers(store)
    assert (unreadable.present, unreadable.layers_json) == (True, None)
    connection.execute("update extension_control_authority_snapshot set layers_json = '[]'")
    present = extension_control_snapshot_layers(store)
    assert (present.present, present.layers_json) == (True, "[]")
    assert store.calls == []
