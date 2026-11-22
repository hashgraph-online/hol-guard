"""The extension-control schema check answers from the native store."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager

import pytest

from codex_plugin_scanner.guard.native_extension_control_schema import extension_control_schema_compatible
from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityError


class _Store:
    def __init__(self, answer: object) -> None:
        self.answer = answer
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.connection = sqlite3.connect(":memory:")
        self.connections = 0

    def _native_store_call(self, method: str, args: dict[str, object]) -> object:
        self.calls.append((method, args))
        return self.answer

    @contextmanager
    def _connect(self):
        self.connections += 1
        with self.connection:
            yield self.connection


def test_a_compatible_marker_answers_without_opening_the_database() -> None:
    store = _Store({"state": "compatible"})

    assert extension_control_schema_compatible(store)
    assert extension_control_schema_compatible(store, require_compatible=False)
    assert store.calls == [("extension_control_schema_state", {})] * 2
    assert store.connections == 0


def test_an_unknown_marker_raises_unless_the_caller_degrades() -> None:
    store = _Store({"state": "incompatible"})

    with pytest.raises(ExtensionControlAuthorityError, match="unsupported or invalid extension control schema"):
        extension_control_schema_compatible(store)
    assert not extension_control_schema_compatible(store, require_compatible=False)
    assert store.connections == 0


def test_a_missing_schema_is_created_before_the_read() -> None:
    store = _Store({"state": "missing"})

    assert extension_control_schema_compatible(store)
    assert store.connections == 1
    tables = {
        row[0] for row in store.connection.execute("select name from sqlite_master where type = 'table'").fetchall()
    }
    assert {"extension_control_schema_migration", "extension_control_authority_snapshot"} <= tables


@pytest.mark.parametrize(
    "answer",
    [None, [], {}, {"state": "unknown"}, {"state": 1}, {"state": "compatible", "extra": True}],
)
def test_a_malformed_answer_fails_closed(answer: object) -> None:
    store = _Store(answer)

    with pytest.raises(sqlite3.DatabaseError, match="extension_control_schema_state"):
        extension_control_schema_compatible(store, require_compatible=False)
    assert store.connections == 0
