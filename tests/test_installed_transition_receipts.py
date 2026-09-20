"""Legacy wheel readback preserves complete receipts without candidate fallback."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.store import GuardStore
from scripts.ci.installed_transition_receipts import AUDITED_BASELINE_SHA, TransitionReceiptReader
from tests.test_native_command_observations import _observations
from tests.test_native_command_observations import _receipt as _bound_receipt
from tests.test_native_decision_receipt import _receipt


class LegacyOwner:
    def __init__(self, path):
        self.path = path

    @contextmanager
    def _connect(self):
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            yield connection


@pytest.mark.parametrize("build_sha", ["", "2e672d2", "a" * 40])
def test_only_exact_audited_build_may_lack_public_getter(build_sha) -> None:
    with pytest.raises(RuntimeError, match="candidate_receipt_getter_missing"):
        TransitionReceiptReader(SimpleNamespace(), build_sha=build_sha)


def test_legacy_complete_receipt_survives_known_nullable_migration(tmp_path) -> None:
    store = GuardStore(tmp_path)
    receipt = _receipt(request_id="baseline-record")
    store.record_native_decision_receipt(receipt)
    legacy = LegacyOwner(store.path)
    with legacy._connect() as connection:
        connection.execute("alter table native_hook_decision_receipts drop column command_extensions_json")
    reader = TransitionReceiptReader(legacy, build_sha=AUDITED_BASELINE_SHA)
    assert reader.read_current(receipt["decision_id"]) == receipt
    assert reader.preserves_prior(receipt)
    with legacy._connect() as connection:
        connection.execute("alter table native_hook_decision_receipts add column command_extensions_json text")
    assert reader.read_current(receipt["decision_id"]) == receipt
    assert reader.preserves_prior(receipt)
    with legacy._connect() as connection:
        connection.execute("update native_hook_decision_receipts set policy_generation = 999")
    assert reader.read_current(receipt["decision_id"]) is None
    assert not reader.preserves_prior(receipt)


@pytest.mark.parametrize("changed_binding", ["altered", "removed", "float", "duplicate"])
def test_baseline_preserves_full_prior_candidate_binding_without_interpreting_it(changed_binding, tmp_path) -> None:
    store = GuardStore(tmp_path)
    receipt = _bound_receipt(_observations())
    store.record_native_decision_receipt(receipt)
    legacy = LegacyOwner(store.path)
    reader = TransitionReceiptReader(legacy, build_sha=AUDITED_BASELINE_SHA)
    # The old build cannot validate or execute this new binding. Its storage
    # preservation check must still compare every previously validated field.
    assert reader.read_current(receipt["decision_id"]) is None
    assert reader.preserves_prior(receipt)
    binding = dict(receipt["command_extensions"])
    if changed_binding == "altered":
        binding["program_digest"] = "f" * 64
    elif changed_binding == "removed":
        del binding["program_digest"]
    elif changed_binding == "float":
        binding["control_revision"] = float(binding["control_revision"])
    encoded = json.dumps(binding)
    if changed_binding == "duplicate":
        encoded = encoded[:-1] + ', "control_revision": 3}'
    with legacy._connect() as connection:
        connection.execute("update native_hook_decision_receipts set command_extensions_json = ?", (encoded,))
    assert not reader.preserves_prior(receipt)


def test_unknown_receipt_columns_never_get_dropped(tmp_path) -> None:
    store = GuardStore(tmp_path)
    receipt = _receipt()
    store.record_native_decision_receipt(receipt)
    legacy = LegacyOwner(store.path)
    reader = TransitionReceiptReader(legacy, build_sha=AUDITED_BASELINE_SHA)
    with legacy._connect() as connection:
        connection.execute("alter table native_hook_decision_receipts add column future_binding text")
    assert reader.read_current(receipt["decision_id"]) is None
    assert not reader.preserves_prior(receipt)
    with pytest.raises(RuntimeError, match="baseline_receipt_schema_changed"):
        TransitionReceiptReader(legacy, build_sha=AUDITED_BASELINE_SHA)


@pytest.mark.parametrize("outcome", ["raised", "missing", "binding_dropped"])
def test_candidate_public_getter_errors_never_use_legacy_sql(outcome) -> None:
    receipt = _bound_receipt(_observations())

    def getter(_identity):
        if outcome == "raised":
            raise OSError("public-getter-failed")
        if outcome == "missing":
            return None
        return {key: value for key, value in receipt.items() if key != "command_extensions"}

    store = SimpleNamespace(
        get_native_decision_receipt=getter,
        _connect=lambda: pytest.fail("candidate failure must never enter legacy SQL"),
    )
    reader = TransitionReceiptReader(store, build_sha="a" * 40)
    if outcome == "raised":
        with pytest.raises(OSError, match="public-getter-failed"):
            reader.preserves_prior(receipt)
    else:
        assert not reader.preserves_prior(receipt)
