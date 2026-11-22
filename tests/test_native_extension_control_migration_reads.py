"""The catalog migration's event and baseline reads, answered by the native store."""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import activation_baseline
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.store_extension_control_authority_catalog_events import (
    already_recorded,
    recorded_writer_version,
)

RECORDED = "extension_control_migration_recorded"
WRITER = "extension_control_catalog_writer_version"
RETAINED = "command_pack_baseline_retained"
METADATA = SimpleNamespace(program_digest="1" * 64, catalog_digest="2" * 64, trust_digest="3" * 64)


def answering(answer):
    calls = []

    def call(method, args):
        calls.append((method, dict(args)))
        return answer

    return SimpleNamespace(_native_store_call=call), calls


@pytest.mark.parametrize("recorded", [True, False])
def test_already_recorded_asks_for_the_revision(recorded):
    store, calls = answering({"recorded": recorded})
    assert already_recorded(store, 7) is recorded
    assert calls == [(RECORDED, {"revision": 7})]


@pytest.mark.parametrize("answer", [None, {}, {"recorded": 1}, {"recorded": True, "extra": 1}])
def test_a_malformed_recorded_answer_is_refused(answer):
    store, _ = answering(answer)
    with pytest.raises(sqlite3.DatabaseError, match=RECORDED):
        already_recorded(store, 7)


@pytest.mark.parametrize("version", ["3.47.0", None])
def test_the_writer_version_is_handed_on(version):
    store, calls = answering({"writer_version": version})
    assert recorded_writer_version(store, "catalog-x") == version
    assert calls == [(WRITER, {"catalog_digest": "catalog-x"})]


@pytest.mark.parametrize(
    "answer", [None, {}, {"writer_version": ""}, {"writer_version": 3}, {"writer_version": "1", "x": 1}]
)
def test_a_malformed_writer_answer_is_refused(answer):
    store, _ = answering(answer)
    with pytest.raises(sqlite3.DatabaseError, match=WRITER):
        recorded_writer_version(store, "catalog-x")


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
