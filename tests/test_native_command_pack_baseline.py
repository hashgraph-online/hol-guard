"""The first pack activation's baseline check, answered by the native store."""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import activation_baseline
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError

RETAINED = "command_pack_baseline_retained"
METADATA = SimpleNamespace(program_digest="1" * 64, catalog_digest="2" * 64, trust_digest="3" * 64)


def answering(answer):
    calls = []

    def call(method, args):
        calls.append((method, dict(args)))
        return answer

    return SimpleNamespace(_native_store_call=call), calls


def test_a_retained_baseline_is_not_sent_again():
    store, calls = answering({"state": "present", "retained": True})
    assert activation_baseline.baseline_request(store, METADATA, recorded_at="unit") is None
    assert calls == [(RETAINED, {})]


def test_a_store_without_the_slot_sends_the_baseline():
    store, _ = answering({"state": "present", "retained": False})
    assert activation_baseline.baseline_request(store, METADATA, recorded_at="unit") == {
        "program_digest": "1" * 64,
        "catalog_digest": "2" * 64,
        "trust_digest": "3" * 64,
        "recorded_at": "unit",
    }


def test_a_missing_schema_fails_as_the_sql_read_did():
    store, _ = answering({"state": "schema_missing"})
    with pytest.raises(sqlite3.OperationalError):
        activation_baseline.baseline_request(store, METADATA, recorded_at="unit")


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {"state": "present"},
        {"state": "present", "retained": 1},
        {"state": "refused", "retained": False},
        {"state": "present", "retained": False, "extra": 1},
    ],
)
def test_a_malformed_baseline_answer_is_refused(answer):
    store, _ = answering(answer)
    with pytest.raises(NativePolicySnapshotError, match=RETAINED):
        activation_baseline.baseline_request(store, METADATA, recorded_at="unit")
