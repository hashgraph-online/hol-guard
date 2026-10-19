"""Authenticated subset transactions; synthetic transport/native admission."""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import (
    activation_baseline,
    activation_journal,
    activation_record,
    activation_store,
    activation_transition,
    preparation,
)
from codex_plugin_scanner.guard.native_command_control_authority_io import hold_command_control_authority_lock
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.store_extension_control_authority_schema import (
    ensure_extension_control_authority_schema,
    extension_control_schema_marker_is_compatible,
)
from tests.native_activation_support import compiled_lifecycle as compiled_lifecycle
from tests.native_activation_support import subset_store
from tests.test_extension_pack_preparation import delivery as delivery

KEY = b"offline-subset-authority-fixture!!"


def committed(delivery, selected):
    prepared = preparation.prepare(
        delivery.verified(), selected, delivery.cache, engine="1" * 64, now=1500, fetch=delivery.fetch
    )
    sealed = activation_record.seal(prepared, key=KEY, revision=1, now=1500)
    # Preserve an actual legacy remote v1 record to qualify schema5 reading.
    import json

    from codex_plugin_scanner.guard.runtime.extension_control_authority import authenticated_record

    legacy = json.loads(sealed[0])
    legacy["schema"] = activation_record.SCHEMA
    legacy.pop("authority_profile")
    sealed = authenticated_record(legacy, key=KEY, purpose=activation_record.PURPOSE)
    return activation_record.open_record(*sealed, key=KEY, directory=delivery.cache), sealed


def test_offline_removal_keeps_authenticated_authority_without_renewal(delivery):
    previous, _ = committed(delivery, ["command.external"])
    calls = len(delivery.calls)
    subset = preparation.prepare(
        previous, [], delivery.cache, engine="1" * 64, retained_extension_ids=["command.external"], now=10000
    )
    assert subset.selected == {"command.core"}
    assert subset.registry_ids == previous.registry_ids
    assert len(delivery.calls) == calls
    draft = activation_transition.stage(previous, subset, verifier_key=KEY, store=subset_store(previous), now=10000)
    result = activation_record.open_record(draft.data, draft.digest, draft.mac, key=KEY, directory=delivery.cache)
    assert result.record()["schema"] == activation_record.SCHEMA_V2
    assert result.record()["expires_at"] == previous.record()["expires_at"] == 2000
    assert result.record()["root_digest"] == previous.record()["root_digest"]
    assert result.selected == {"command.core"}


def test_offline_cached_but_uncommitted_policy_is_never_activatable(delivery):
    previous, _ = committed(delivery, [])
    # Even valid downloaded objects do not grant activation authority.
    preparation.prepare(
        delivery.verified(), ["command.external"], delivery.cache, engine="1" * 64, now=1500, fetch=delivery.fetch
    )
    with pytest.raises(ValueError, match="uncommitted"):
        preparation.prepare(previous, ["command.external"], delivery.cache, engine="1" * 64, now=10000)


def test_subset_writes_schema6_and_keeps_schema5_readable(delivery, monkeypatch):
    previous, sealed = committed(delivery, ["command.external"])
    store = SimpleNamespace(guard_home=delivery.cache.parent / "device")
    store.guard_home.mkdir(mode=0o700)
    monkeypatch.setattr(activation_store, "directory_for_store", lambda store: delivery.cache)
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    ensure_extension_control_authority_schema(connection, activate_packs=True)
    connection.execute("insert into extension_command_pack_activation values (1,1,?,?,?,?)", (*sealed, "unit"))
    connection.commit()
    store._connect = lambda: connection
    store._policy_integrity_secret_material = lambda **kwargs: (b"k" * 32, "test")
    monkeypatch.setattr("codex_plugin_scanner.guard.native_command_control_authority_store._key", lambda store: KEY)
    assert activation_store.read(store).record_digest == previous.record_digest
    subset = preparation.prepare(previous, [], delivery.cache, engine="1" * 64, now=10000)
    protected = subset_store(previous)
    store._policy_integrity_secret_store = protected._policy_integrity_secret_store
    store._should_skip_policy_integrity_keychain_access = protected._should_skip_policy_integrity_keychain_access
    store._build_scoped_secret_ref = protected._build_scoped_secret_ref
    store._get_policy_integrity_secret_from_store = protected._get_policy_integrity_secret_from_store
    draft = activation_transition.stage(previous, subset, verifier_key=KEY, store=store, now=10000)
    with hold_command_control_authority_lock(store.guard_home), connection:
        activation_store.write_in_transaction(store, connection, draft, verifier_key=KEY, recorded_at="unit", now=10000)
    marker = connection.execute("select version,checksum from extension_control_schema_migration").fetchone()
    assert marker["version"] == 6
    assert extension_control_schema_marker_is_compatible(*marker)
    assert activation_store.read(store).selected == {"command.core"}
    # New readers preserve the floor and baseline reservation cannot overwrite it.
    with hold_command_control_authority_lock(store.guard_home), connection:
        activation_baseline.reserve_legacy_baseline(store, connection, None, key=KEY, recorded_at="unit")
    assert activation_store.read(store).record_digest == draft.digest
    with (
        hold_command_control_authority_lock(store.guard_home),
        connection,
        pytest.raises(NativePolicySnapshotError, match="conflict"),
    ):
        activation_store.write_in_transaction(store, connection, draft, verifier_key=KEY, recorded_at="unit", now=10000)


def test_subset_reservation_fences_old_writers_before_anchor(delivery, monkeypatch):
    previous, sealed = committed(delivery, ["command.external"])
    store = SimpleNamespace(guard_home=delivery.cache.parent / "device")
    store.guard_home.mkdir(mode=0o700)
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    ensure_extension_control_authority_schema(connection, activate_packs=True)
    connection.execute("insert into extension_command_pack_activation values (1,1,?,?,?,?)", (*sealed, "unit"))
    connection.commit()
    monkeypatch.setattr(activation_journal, "directory_for_store", lambda store: delivery.cache)
    monkeypatch.setattr(activation_journal, "_key", lambda store: KEY)
    subset = preparation.prepare(previous, [], delivery.cache, engine="1" * 64, now=10000)
    protected = subset_store(previous)
    store._policy_integrity_secret_material = protected._policy_integrity_secret_material
    store._policy_integrity_secret_store = protected._policy_integrity_secret_store
    store._should_skip_policy_integrity_keychain_access = protected._should_skip_policy_integrity_keychain_access
    store._build_scoped_secret_ref = protected._build_scoped_secret_ref
    store._get_policy_integrity_secret_from_store = protected._get_policy_integrity_secret_from_store
    draft = activation_transition.stage(previous, subset, verifier_key=KEY, store=store, now=10000)
    with hold_command_control_authority_lock(store.guard_home), connection:
        activation_journal.reserve(
            store,
            connection,
            draft,
            control_revision=2,
            snapshot_digest="a" * 64,
            catalog_digest=subset.metadata.catalog_digest,
            recorded_at="unit",
            now=10000,
        )
    assert connection.execute("select version from extension_control_schema_migration").fetchone()[0] == 6
