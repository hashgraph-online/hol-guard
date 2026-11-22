"""A stored native decision receipt is looked up by the native store."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.native_guard_store import NativeGuardStoreUnavailable
from codex_plugin_scanner.guard.store import GuardStore

_ID = "a" * 64


def _unavailable(reason: str) -> NativeGuardStoreUnavailable:
    error = NativeGuardStoreUnavailable(f"unavailable ({reason})")
    error.reason = reason
    return error


def test_the_read_sends_only_the_decision_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path)
    calls: list[tuple[str, object]] = []

    def native(method: str, args: object, **_kwargs: Any) -> object:
        calls.append((method, args))
        return None

    monkeypatch.setattr(store, "_native_store_call", native)

    assert store.get_native_decision_receipt(_ID) is None
    assert calls == [("get_native_decision_receipt", {"decision_id": _ID})]


@pytest.mark.parametrize("decision_id", ["missing", "A" * 64, "a" * 63, ""])
def test_a_malformed_id_never_reaches_the_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, decision_id: str
) -> None:
    store = GuardStore(tmp_path)

    def native(_method: str, _args: object, **_kwargs: Any) -> object:
        raise AssertionError("the store must not be asked")

    monkeypatch.setattr(store, "_native_store_call", native)

    assert store.get_native_decision_receipt(decision_id) is None


def test_an_unknown_id_reads_as_no_receipt(tmp_path: Path) -> None:
    assert GuardStore(tmp_path).get_native_decision_receipt(_ID) is None


def test_a_cell_outside_the_receipt_types_reads_as_no_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path)

    def native(_method: str, _args: object, **_kwargs: Any) -> object:
        raise _unavailable("native_guard_store_cell_invalid")

    monkeypatch.setattr(store, "_native_store_call", native)

    assert store.get_native_decision_receipt(_ID) is None


def test_an_unavailable_runtime_is_not_read_as_no_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path)

    def native(_method: str, _args: object, **_kwargs: Any) -> object:
        raise _unavailable("native_guard_store_unavailable")

    monkeypatch.setattr(store, "_native_store_call", native)

    with pytest.raises(NativeGuardStoreUnavailable):
        store.get_native_decision_receipt(_ID)


@pytest.mark.parametrize("answer", [[], "row", 7, True, {1: "x"}])
def test_a_malformed_answer_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    store = GuardStore(tmp_path)

    def native(_method: str, _args: object, **_kwargs: Any) -> object:
        return answer

    monkeypatch.setattr(store, "_native_store_call", native)

    with pytest.raises(RuntimeError, match="returned no answer"):
        store.get_native_decision_receipt(_ID)


def test_a_row_that_fails_validation_reads_as_no_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path)

    def native(_method: str, _args: object, **_kwargs: Any) -> object:
        return {"decision_id": _ID, "workspace_bound": 2}

    monkeypatch.setattr(store, "_native_store_call", native)

    assert store.get_native_decision_receipt(_ID) is None
