"""The publisher reuses a command-control binding only while its inputs are unchanged."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_command_control_binding as binding_module
from codex_plugin_scanner.guard import native_command_control_binding_memo as memo
from codex_plugin_scanner.guard.catalog_delivery import lifecycle
from codex_plugin_scanner.guard.native_command_control_authority import AUTHORITY_FILE_NAME
from codex_plugin_scanner.guard.native_command_control_authority_store import _key
from codex_plugin_scanner.guard.native_policy_snapshot_windows_support import _runtime_state_directory
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_extension_control_authority_schema import (
    ensure_extension_control_authority_schema,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the memo keeps nothing on Windows")


_INPUT_KEY = memo.input_key


@pytest.fixture(autouse=True)
def _reuse(_command_control_binding_memo: None, monkeypatch: pytest.MonkeyPatch) -> None:
    # Runs after the suite-wide fixture that stubs the key out.
    monkeypatch.setattr(memo, "input_key", _INPUT_KEY)


def _store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GuardStore:
    store = GuardStore(tmp_path)
    with sqlite3.connect(store.path) as connection:
        ensure_extension_control_authority_schema(connection, activate_packs=True)
    monkeypatch.setattr(lifecycle, "runtime_fingerprint", lambda: ((1, 2, 3, 4, 5),))
    _key(store)
    return store


def _pending(store: GuardStore, revision: int) -> None:
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "insert into extension_command_pack_pending values (?, '{}', ?, ?, '{}', ?, ?)",
            (revision, "a" * 64, "b" * 64, "c" * 64, "d" * 64),
        )


def test_input_key_holds_until_an_input_moves(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path, monkeypatch)
    first = memo.input_key(store)
    assert first is not None
    assert memo.input_key(store) == first

    _pending(store, 1)
    second = memo.input_key(store)
    assert second not in {None, first}

    state = _runtime_state_directory(store.guard_home)
    state.mkdir(parents=True, exist_ok=True)
    (state / AUTHORITY_FILE_NAME).write_text("{}")
    third = memo.input_key(store)
    assert third not in {None, second}

    monkeypatch.setattr(lifecycle, "runtime_fingerprint", lambda: ((1, 2, 3, 4, 6),))
    assert memo.input_key(store) not in {None, third}


def test_input_key_moves_when_only_a_row_payload_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A payload edited in place, with its digest and MAC left alone, fails
    # verification on a full read; the memo must not serve over it.
    store = _store(tmp_path, monkeypatch)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "insert into extension_command_pack_activation values (1, 1, '{}', ?, ?, '2026-01-01T00:00:00Z')",
            ("a" * 64, "b" * 64),
        )
    _pending(store, 1)
    before = memo.input_key(store)
    for statement in (
        "update extension_command_pack_activation set record_json = '{\"edited\":true}'",
        "update extension_command_pack_pending set link_json = '{\"edited\":true}'",
    ):
        with sqlite3.connect(store.path) as connection:
            connection.execute(statement)
        after = memo.input_key(store)
        assert after not in {None, before}
        before = after


def test_input_key_is_unavailable_when_an_input_cannot_be_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path, monkeypatch)

    def missing() -> tuple[tuple[int, ...], ...]:
        raise FileNotFoundError("runtime")

    monkeypatch.setattr(lifecycle, "runtime_fingerprint", missing)
    assert memo.input_key(store) is None


def test_input_key_is_unavailable_on_windows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path, monkeypatch)
    monkeypatch.setattr(sys, "platform", "win32")
    assert memo.input_key(store) is None


def test_kept_binding_serves_only_its_key_runtime_and_interval(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path)
    keys = iter(["k1", "k1", "k1", "k2", "k1", "k1"])
    monkeypatch.setattr(memo, "input_key", lambda _store: next(keys))
    runtime, other = object(), object()
    clock = [100.0]
    monkeypatch.setattr(memo.time, "monotonic", lambda: clock[0])

    key, kept = memo.lookup(store, runtime)
    assert kept is None
    memo.keep(store, key, {"revision": 3, "layers": [{"kind": "local"}]}, runtime)

    _, served = memo.lookup(store, runtime)
    assert served is not None
    assert served[1] is runtime
    served[0]["layers"].append({"kind": "tampered"})
    assert memo.lookup(store, other)[1] is None
    assert memo.lookup(store, runtime)[1] is None  # k2
    _, again = memo.lookup(store, runtime)
    assert again is not None
    assert again[0] == {"revision": 3, "layers": [{"kind": "local"}]}
    clock[0] += 60.0
    assert memo.lookup(store, runtime)[1] is None


def test_unkeyed_read_is_never_kept(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path)
    monkeypatch.setattr(memo, "input_key", lambda _store: None)
    runtime = object()
    key, _ = memo.lookup(store, runtime)
    memo.keep(store, key, {"revision": 3}, runtime)
    assert memo.lookup(store, runtime) == (None, None)


def test_binding_read_skips_the_full_read_while_inputs_hold(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_command_control_projection
    from codex_plugin_scanner.guard.catalog_delivery import projection

    store = GuardStore(tmp_path)
    key = ["k1"]
    monkeypatch.setattr(memo, "input_key", lambda _store: key[0])
    reads: list[object] = []
    runtime = object()
    monkeypatch.setattr(projection, "capture", lambda _store: ("metadata", "registry", None))

    def read(_store, _metadata, previous, **_kwargs):
        reads.append(previous)
        return {"revision": len(reads)}, runtime

    monkeypatch.setattr(native_command_control_projection, "read_control_projection", read)
    monkeypatch.setattr(lifecycle, "session", _NoSession)

    first = binding_module.read_native_command_control_binding(store)
    assert binding_module.read_native_command_control_binding(store, runtime) == first
    assert reads == [None]
    key[0] = "k2"
    assert binding_module.read_native_command_control_binding(store, runtime) == ({"revision": 2}, runtime)
    assert reads == [None, runtime]


class _NoSession:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *_args: object) -> None:
        return None
