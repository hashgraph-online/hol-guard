"""Real SQLite migration and round-trip checks for native command bindings."""

from __future__ import annotations

import copy
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_decision_receipt import validate_native_decision_receipt
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_native_decision_receipts import StoreNativeDecisionReceiptsMixin
from tests.test_native_command_observations import _observations, _receipt


def test_stored_command_receipt_round_trips_the_complete_identity(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    receipt = _receipt(_observations())
    assert store.record_native_decision_receipt(receipt)
    assert store.get_native_decision_receipt(receipt["decision_id"]) == receipt
    assert validate_native_decision_receipt(store.get_native_decision_receipt(receipt["decision_id"])) == receipt
    with store._connect() as connection:
        row = connection.execute(
            "select command_extensions_json from native_hook_decision_receipts where decision_id = ?",
            (receipt["decision_id"],),
        ).fetchone()
    assert row[0] == json.dumps(receipt["command_extensions"], sort_keys=True, separators=(",", ":"))
    assert "ollama" not in row[0]  # Binding contains digests/counts, not command or observation text.
    assert store.record_native_decision_receipt(receipt)
    assert store.native_decision_receipt_count() == 1


def test_legacy_schema_upgrade_preserves_receipts_without_inventing_binding(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    legacy = _receipt(None)
    assert store.record_native_decision_receipt(legacy)
    with store._connect() as connection:
        connection.execute("alter table native_hook_decision_receipts drop column command_extensions_json")
        connection.execute("delete from schema_migrations where version = 28")

    reopened = GuardStore(tmp_path, daemon_managed_schema=True)
    assert reopened.get_native_decision_receipt(legacy["decision_id"]) == legacy
    current = _receipt(_observations())
    assert reopened.record_native_decision_receipt(current)
    reopened = GuardStore(tmp_path, daemon_managed_schema=True)
    assert reopened.get_native_decision_receipt(current["decision_id"]) == current
    assert reopened.get_native_decision_receipt(legacy["decision_id"]) == legacy
    with reopened._connect() as connection:
        assert connection.execute("select count(*) from schema_migrations where version = 28").fetchone()[0] == 1
        assert (
            connection.execute(
                "select command_extensions_json from native_hook_decision_receipts where decision_id = ?",
                (legacy["decision_id"],),
            ).fetchone()[0]
            is None
        )


@pytest.mark.parametrize(
    "field,value",
    (
        ("program_digest", "e" * 64),
        ("catalog_digest", "e" * 64),
        ("trust_digest", "e" * 64),
        ("control_revision", 4),
        ("managed_control_revision", 6),
        ("control_effective_digest", "e" * 64),
        ("observations_digest", "e" * 64),
        ("observation_count", 2),
        ("uncertainty_count", 1),
    ),
)
def test_changed_stored_binding_cannot_validate_against_the_original_receipt(
    tmp_path: Path, field: str, value: object
) -> None:
    store = GuardStore(tmp_path)
    receipt = _receipt(_observations())
    store.record_native_decision_receipt(receipt)
    changed = {**receipt["command_extensions"], field: value}
    with store._connect() as connection:
        connection.execute(
            "update native_hook_decision_receipts set command_extensions_json = ? where decision_id = ?",
            (json.dumps(changed), receipt["decision_id"]),
        )
    assert store.get_native_decision_receipt(receipt["decision_id"]) is None


def test_binding_capture_detaches_mutable_caller_data_before_transaction(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    receipt = _receipt(_observations())
    expected = copy.deepcopy(receipt)

    class MutatingOwner(StoreNativeDecisionReceiptsMixin):
        @contextmanager
        def _connect(self):
            receipt["command_extensions"]["program_digest"] = "e" * 64
            with store._connect() as connection:
                yield connection

    assert MutatingOwner().record_native_decision_receipts([receipt]) == (expected["decision_id"],)
    assert store.get_native_decision_receipt(expected["decision_id"]) == expected


def test_invalid_or_oversized_binding_is_not_accepted_as_persisted_evidence(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    receipt = _receipt(_observations())
    store.record_native_decision_receipt(receipt)
    with store._connect() as connection:
        connection.execute(
            "update native_hook_decision_receipts set command_extensions_json = ?",
            ("{!",),
        )
    assert store.get_native_decision_receipt(receipt["decision_id"]) is None
    with store._connect() as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute("update native_hook_decision_receipts set command_extensions_json = ?", ("x" * 2049,))
    assert store.get_native_decision_receipt("missing") is None
