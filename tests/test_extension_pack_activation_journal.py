"""Crash boundaries for pack drafts linked to the existing control anchor."""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import (
    activation_baseline,
    activation_journal,
    activation_store,
    activation_transition,
    preparation,
)
from codex_plugin_scanner.guard.native_command_control_authority_io import hold_command_control_authority_lock
from codex_plugin_scanner.guard.native_command_control_authority_store import _key
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    TRANSITION_PURPOSE,
    AuthorityAnchor,
    AuthorityPhase,
    authenticated_record,
)
from codex_plugin_scanner.guard.store_extension_control_authority_schema import (
    ensure_extension_control_authority_schema,
)
from tests.test_extension_pack_preparation import delivery as delivery


@pytest.fixture
def journal(delivery):
    home = delivery.cache.parent / "journal-device"
    home.mkdir(mode=0o700)
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    anchor = SimpleNamespace(current=None)
    store = SimpleNamespace(
        guard_home=home,
        _connect=lambda: connection,
        _policy_integrity_secret_material=lambda *, create: (b"k" * 32, "test"),
        _authority_key=lambda *, required: b"a" * 32,
        _read_anchor=lambda *, key: anchor.current,
    )
    ensure_extension_control_authority_schema(connection)
    connection.commit()
    prepared = preparation.prepare(
        delivery.verified(),
        [],
        activation_store.prepare_directory_for_store(store),
        engine="1" * 64,
        now=1500,
        fetch=delivery.fetch,
    )
    draft = activation_transition.stage(
        None, prepared, verifier_key=_key(store), installed_source=prepared.source_sha, now=1500
    )
    payload = {"command_pack_record_digest": draft.digest}
    data, digest, mac = authenticated_record(payload, key=b"a" * 32, purpose=TRANSITION_PURPOSE)
    transition = {
        "revision": 1,
        "snapshot_digest": "e" * 64,
        "catalog_digest": prepared.metadata.catalog_digest,
        "created_at": "unit",
        "transition_json": data,
        "transition_digest": digest,
        "transition_mac": mac,
    }
    return SimpleNamespace(
        store=store, connection=connection, anchor=anchor, prepared=prepared, draft=draft, transition=transition
    )


def reserve(value):
    activation_journal.reserve(
        value.store,
        value.connection,
        value.draft,
        control_revision=1,
        snapshot_digest=value.transition["snapshot_digest"],
        catalog_digest=value.transition["catalog_digest"],
        recorded_at="unit",
        now=1500,
    )


def test_first_activation_cannot_omit_the_installed_source_floor(journal):
    with pytest.raises(ValueError, match="installed source floor"):
        activation_transition.stage(None, journal.prepared, verifier_key=_key(journal.store), now=1500)


def test_packless_transition_does_not_add_an_exclusive_lease_requirement(journal):
    data, digest, mac = authenticated_record({}, key=b"a" * 32, purpose=TRANSITION_PURPOSE)
    transition = {**journal.transition, "transition_json": data, "transition_digest": digest, "transition_mac": mac}
    with hold_command_control_authority_lock(journal.store.guard_home, shared=True):
        activation_journal.finish(journal.store, journal.connection, transition)


def test_published_object_entry_is_durable_for_both_new_and_competing_writers(tmp_path, monkeypatch):
    import hashlib

    from codex_plugin_scanner.guard.catalog_delivery import pack_store

    directory = tmp_path / "objects"
    directory.mkdir()
    data = b'{"fixture":true}\n'
    digest = hashlib.sha256(data).hexdigest()
    synchronized = []
    monkeypatch.setattr(pack_store, "durable_directory", lambda path: synchronized.append(path))
    assert pack_store.publish_object(directory, digest, data) is True
    assert pack_store.publish_object(directory, digest, data) is False
    assert synchronized == [directory, directory]


def test_reservation_fences_old_writers_but_keeps_the_authenticated_legacy_baseline(journal):
    value = journal
    with hold_command_control_authority_lock(value.store.guard_home), value.connection:
        reserve(value)
    row = value.connection.execute("select * from extension_command_pack_activation").fetchone()
    assert activation_baseline.verify(row, _key(value.store))["revision"] == 0
    assert activation_store.read(value.store) is None
    assert value.connection.execute("select version from extension_control_schema_migration").fetchone()[0] == 5
    with hold_command_control_authority_lock(value.store.guard_home), value.connection:
        with pytest.raises(NativePolicySnapshotError, match="unanchored"):
            activation_journal.finish(value.store, value.connection, value.transition)
        activation_journal.abandon(value.connection, 1)
    assert activation_store.read(value.store) is None
    assert value.connection.execute("select count(*) from extension_command_pack_pending").fetchone()[0] == 0


def test_anchored_recovery_installs_with_controls_atomically_and_needs_no_fetch(journal, monkeypatch):
    value = journal
    with hold_command_control_authority_lock(value.store.guard_home), value.connection:
        reserve(value)
    value.anchor.current = AuthorityAnchor(1, value.transition["snapshot_digest"], AuthorityPhase.ANCHORED)
    # The reservation was admitted while fresh. An anchored crash may recover
    # offline after expiry without silently losing the approved protection.
    monkeypatch.setattr("time.time", lambda: 9000000)
    with hold_command_control_authority_lock(value.store.guard_home):
        with pytest.raises(RuntimeError, match="crash"), value.connection:
            activation_journal.finish(value.store, value.connection, value.transition)
            raise RuntimeError("crash before control snapshot commit")
        assert activation_store.read(value.store) is None
        with value.connection:
            activation_journal.finish(value.store, value.connection, value.transition)
    assert activation_store.read(value.store).metadata == value.prepared.metadata
    assert value.connection.execute("select count(*) from extension_command_pack_pending").fetchone()[0] == 0


def test_missing_reservation_cannot_commit_pack_bound_controls(journal):
    value = journal
    with (
        hold_command_control_authority_lock(value.store.guard_home),
        value.connection,
        pytest.raises(NativePolicySnapshotError, match="transition_missing"),
    ):
        activation_journal.finish(value.store, value.connection, value.transition)


def test_reservation_is_bound_to_the_exact_control_snapshot(journal):
    value = journal
    with hold_command_control_authority_lock(value.store.guard_home), value.connection:
        reserve(value)
    value.transition["snapshot_digest"] = "f" * 64
    value.anchor.current = AuthorityAnchor(1, value.transition["snapshot_digest"], AuthorityPhase.ANCHORED)
    with (
        hold_command_control_authority_lock(value.store.guard_home),
        value.connection,
        pytest.raises(NativePolicySnapshotError, match="transition_mismatch"),
    ):
        activation_journal.finish(value.store, value.connection, value.transition)
