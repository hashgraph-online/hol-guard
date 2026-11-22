"""The activation slot read goes through the native store and checks the answer it gets back."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import activation_store
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError

ROW = {
    "revision": 3,
    "record_json": "{}",
    "record_digest": "a" * 64,
    "record_mac": "b" * 64,
    "recorded_at": "unit",
}


def _store(answer):
    calls = []

    def call(method, args):
        calls.append((method, args))
        return answer

    return SimpleNamespace(_native_store_call=call), calls


def test_a_store_before_the_pack_schema_has_no_slot():
    store, calls = _store({"state": "absent"})
    assert activation_store.read_slot(store) is None
    assert calls == [("read_command_pack_activation", {})]


@pytest.mark.parametrize("code", ["native_command_pack_schema_invalid", "native_command_pack_activation_missing"])
def test_a_broken_slot_raises_its_own_code(code):
    store, _ = _store({"state": "refused", "code": code})
    with pytest.raises(NativePolicySnapshotError, match=f"^{code}$"):
        activation_store.read_slot(store)


def test_a_present_slot_comes_back_as_stored():
    store, _ = _store({"state": "present", "row": dict(ROW)})
    assert activation_store.read_slot(store) == ROW


@pytest.mark.parametrize(
    "answer",
    [
        None,
        [],
        {},
        {"state": "unknown"},
        {"state": []},
        {"state": {}},
        {"state": None},
        {"state": "absent", "row": dict(ROW)},
        {"state": "missing"},
        {"state": "refused"},
        {"state": "refused", "code": "native_other"},
        {"state": "refused", "code": "native_command_pack_activation_missing", "extra": 1},
        {"state": "present"},
        {"state": "present", "row": None},
        {"state": "present", "row": {**ROW, "extra": 1}},
        {"state": "present", "row": {key: value for key, value in ROW.items() if key != "recorded_at"}},
        {"state": "present", "row": {**ROW, "revision": True}},
        {"state": "present", "row": {**ROW, "revision": -1}},
        {"state": "present", "row": {**ROW, "revision": "3"}},
        {"state": "present", "row": {**ROW, "record_mac": None}},
        {"state": "present", "row": dict(ROW), "extra": 1},
    ],
)
def test_a_malformed_answer_is_refused(answer):
    store, _ = _store(answer)
    with pytest.raises(NativePolicySnapshotError, match="returned no answer"):
        activation_store.read_slot(store)
