"""Public SQLite exceptions preserve the native error record."""

from __future__ import annotations

import json
import math
import sqlite3
from contextlib import contextmanager

import pytest

from codex_plugin_scanner.guard import native_continuation_authority as native
from codex_plugin_scanner.guard import store_continuation


@pytest.mark.parametrize(
    ("exception", "code", "prefix", "expected_name"),
    [
        ("InternalError", sqlite3.SQLITE_INTERNAL, "SQLITE_INTERNAL", "SQLITE_INTERNAL"),
        ("InternalError", sqlite3.SQLITE_NOTFOUND, "SQLITE_NOTFOUND", "SQLITE_NOTFOUND"),
        ("InterfaceError", sqlite3.SQLITE_RANGE, "SQLITE_RANGE", "SQLITE_RANGE"),
        ("DatabaseError", sqlite3.SQLITE_AUTH, "SQLITE_AUTH", "SQLITE_AUTH"),
        ("OperationalError", sqlite3.SQLITE_BUSY, "SQLITE_BUSY", "SQLITE_BUSY"),
        ("IntegrityError", sqlite3.SQLITE_CONSTRAINT_UNIQUE, "SQLITE_CONSTRAINT", "SQLITE_CONSTRAINT_UNIQUE"),
    ],
)
def test_sqlite_error_transport(monkeypatch, exception, code, prefix, expected_name):
    monkeypatch.setattr(
        native,
        "native_runner_authority",
        lambda *_: {
            "exception": "sqlite3." + exception,
            "error": "original SQLite message",
            "sqlite_errorcode": code,
            "sqlite_errorname_prefix": prefix,
        },
    )
    with pytest.raises(getattr(sqlite3, exception)) as caught:
        native.continuation_authority("store_claim")
    assert str(caught.value) == "original SQLite message"
    assert caught.value.sqlite_errorcode == code
    assert caught.value.sqlite_errorname == expected_name


def test_lone_surrogate_metadata_crosses_the_utf8_envelope(monkeypatch):
    metadata = json.loads('{"label": "a\\ud800b", "nested": [1.5, NaN], "plain": "caf\\u00e9"}')
    captured: dict[str, object] = {}

    def fake_native(_kind, carrier, _home):
        captured.update(carrier)
        json.dumps(carrier, ensure_ascii=False).encode("utf-8")
        return {"operation_update": {"metadata": {"label": None, "nested": [1.5, None], "plain": "café"}}}

    monkeypatch.setattr(native, "native_runner_authority", fake_native)
    result = native.continuation_authority("project", operation={"metadata": metadata})
    assert captured["operation"] == {"metadata": {"label": None, "nested": [1.5, None], "plain": "café"}}
    assert captured["operation_metadata_nonfinite"] == [(["label"], '"a\\ud800b"'), (["nested", 1], "NaN")]
    restored = result["operation_update"]["metadata"]
    assert restored["label"] == metadata["label"]
    assert math.isnan(restored["nested"][1])
    assert json.dumps(restored, sort_keys=True) == json.dumps(metadata, sort_keys=True)


class _GateStore:
    guard_home = None
    path = "guard.db"

    def __init__(self) -> None:
        self.recovered: list[BaseException] = []
        self.gate_held = False

    @contextmanager
    def _hold_storage_gate(self, *, exclusive: bool):
        assert not exclusive
        self.gate_held = True
        try:
            yield
        finally:
            self.gate_held = False

    def _repair_store_permissions(self) -> None:
        return None

    def _recover_fatal_sqlite_store(self, error: BaseException) -> bool:
        assert not self.gate_held
        self.recovered.append(error)
        return True


def test_expired_storage_deadline_never_reaches_the_native_store(monkeypatch):
    monkeypatch.setattr(store_continuation, "sqlite_connect_timeout_seconds", lambda: 0.0)
    monkeypatch.setattr(store_continuation, "continuation_authority", lambda *_a, **_k: pytest.fail("native called"))
    with pytest.raises(TimeoutError, match=r"Guard storage operation deadline expired\."):
        store_continuation.continuation_store_call(_GateStore(), "store_claim")


def test_fatal_native_sqlite_error_recovers_the_store_then_reraises(monkeypatch):
    failure = sqlite3.DatabaseError("database disk image is malformed")

    def fail(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(store_continuation, "sqlite_connect_timeout_seconds", lambda: 2.0)
    monkeypatch.setattr(store_continuation, "continuation_authority", fail)
    store = _GateStore()
    with pytest.raises(sqlite3.DatabaseError) as caught:
        store_continuation.continuation_store_call(store, "store_finalize")
    assert caught.value is failure
    assert store.recovered == [failure]
