"""Activation and its incompatible-writer floor share the control transaction."""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import (
    activation_record,
    activation_store,
    activation_transition,
    preparation,
)
from codex_plugin_scanner.guard.native_command_control_authority_io import hold_command_control_authority_lock
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.store_extension_control_authority_schema import (
    ensure_extension_control_authority_schema,
)
from tests.native_activation_support import compiled_lifecycle as compiled_lifecycle
from tests.native_activation_support import seed
from tests.test_extension_pack_preparation import delivery as delivery


def test_activation_transaction_rechecks_predecessor_and_keeps_schema_floor_atomic(delivery):
    store = SimpleNamespace(guard_home=delivery.cache.parent / "device")
    store.guard_home.mkdir(mode=0o700)
    seed(store)
    directory = activation_store.directory_for_store(store)
    prepared = preparation.prepare(delivery.verified(), [], directory, engine="1" * 64, now=1500, fetch=delivery.fetch)
    key = b"activation transaction fixture".ljust(32, b"x")
    draft = activation_transition.stage(None, prepared, verifier_key=key, store=store, now=1500)
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    ensure_extension_control_authority_schema(connection)
    connection.commit()
    with pytest.raises(NativePolicySnapshotError, match="lease_missing"):
        activation_store.write_in_transaction(store, connection, draft, verifier_key=key, recorded_at="unit", now=1500)
    with hold_command_control_authority_lock(store.guard_home):
        with pytest.raises(RuntimeError, match="crash"), connection:
            activation_store.write_in_transaction(
                store, connection, draft, verifier_key=key, recorded_at="unit", now=1500
            )
            raise RuntimeError("crash before control commit")
        assert connection.execute("select version from extension_control_schema_migration").fetchone()[0] == 4
        with connection:
            activation_store.write_in_transaction(
                store, connection, draft, verifier_key=key, recorded_at="unit", now=1500
            )
    assert connection.execute("select version from extension_control_schema_migration").fetchone()[0] == 6
    row = connection.execute("select * from extension_command_pack_activation").fetchone()
    opened = activation_record.open_record(
        row["record_json"], row["record_digest"], row["record_mac"], key=key, directory=directory
    )
    assert opened.metadata == prepared.metadata
    with (
        hold_command_control_authority_lock(store.guard_home),
        pytest.raises(NativePolicySnapshotError, match="conflict"),
        connection,
    ):
        activation_store.write_in_transaction(store, connection, draft, verifier_key=key, recorded_at="unit", now=1500)
    with (
        hold_command_control_authority_lock(store.guard_home, shared=True),
        pytest.raises(NativePolicySnapshotError, match="lease_missing"),
    ):
        activation_store.write_in_transaction(store, connection, draft, verifier_key=key, recorded_at="unit", now=1500)
