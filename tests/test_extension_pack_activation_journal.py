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
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityAnchor, AuthorityPhase
from codex_plugin_scanner.guard.store_extension_control_authority_schema import (
    ensure_extension_control_authority_schema,
)
from tests.extension_control_records import TRANSITION_PURPOSE, authenticated_record
from tests.native_activation_support import compiled_lifecycle as compiled_lifecycle
from tests.native_activation_support import seed
from tests.test_extension_pack_preparation import delivery as delivery
from tests.test_native_pack_upgrade import release as release


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
    seed(store)
    prepared = preparation.prepare(
        delivery.verified(),
        [],
        activation_store.prepare_directory_for_store(store),
        engine="1" * 64,
        now=1500,
        fetch=delivery.fetch,
    )
    draft = activation_transition.stage(None, prepared, verifier_key=_key(store), store=store, now=1500)
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
        store=store,
        connection=connection,
        anchor=anchor,
        prepared=prepared,
        draft=draft,
        transition=transition,
        pack=draft.digest,
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


def test_first_activation_cannot_omit_the_protected_floor(journal):
    journal.store._policy_integrity_secret_store.values.clear()
    with pytest.raises(ValueError, match="protected_floor_missing"):
        activation_transition.stage(
            None, journal.prepared, verifier_key=_key(journal.store), store=journal.store, now=1500
        )


def test_packless_transition_does_not_add_an_exclusive_lease_requirement(journal):
    data, digest, mac = authenticated_record({}, key=b"a" * 32, purpose=TRANSITION_PURPOSE)
    transition = {**journal.transition, "transition_json": data, "transition_digest": digest, "transition_mac": mac}
    with hold_command_control_authority_lock(journal.store.guard_home, shared=True):
        activation_journal.finish(journal.store, journal.connection, transition, expected_pack=None)


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
    assert value.connection.execute("select version from extension_control_schema_migration").fetchone()[0] == 6
    with hold_command_control_authority_lock(value.store.guard_home), value.connection:
        with pytest.raises(NativePolicySnapshotError, match="unanchored"):
            activation_journal.finish(value.store, value.connection, value.transition, expected_pack=value.pack)
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
            activation_journal.finish(value.store, value.connection, value.transition, expected_pack=value.pack)
            raise RuntimeError("crash before control snapshot commit")
        assert activation_store.read(value.store) is None
        with value.connection:
            activation_journal.finish(value.store, value.connection, value.transition, expected_pack=value.pack)
    assert activation_store.read(value.store).metadata == value.prepared.metadata
    assert value.connection.execute("select count(*) from extension_command_pack_pending").fetchone()[0] == 0


def test_a_runtime_outage_while_resuming_keeps_the_pending_transition(journal, monkeypatch):
    """An outage says nothing about the record, so it must not read as damage.

    `UnverifiablePackTransitionError` is what lets recovery reset control
    authority and discard the pending transition. A missing, unverifiable or
    timed-out runtime has to stay retryable instead.
    """
    from codex_plugin_scanner.guard.catalog_delivery import lifecycle

    value = journal
    with hold_command_control_authority_lock(value.store.guard_home), value.connection:
        reserve(value)
    value.anchor.current = AuthorityAnchor(1, value.transition["snapshot_digest"], AuthorityPhase.ANCHORED)
    before = tuple(value.connection.iterdump())

    def unavailable(*args, **kwargs):
        raise lifecycle.NativePackLifecycleUnavailableError("native_pack_lifecycle_unavailable: feature unavailable")

    # `compiled_lifecycle` pins the runtime through the same `monkeypatch`
    # instance, so undoing here would drop the retry onto the production
    # lifecycle. Restore the one name this test replaced.
    available = lifecycle.record
    monkeypatch.setattr(lifecycle, "record", unavailable)
    with (
        hold_command_control_authority_lock(value.store.guard_home),
        pytest.raises(lifecycle.NativePackLifecycleUnavailableError, match="unavailable"),
        value.connection,
    ):
        activation_journal.finish(value.store, value.connection, value.transition, expected_pack=value.pack)
    assert tuple(value.connection.iterdump()) == before
    monkeypatch.setattr(lifecycle, "record", available)
    with hold_command_control_authority_lock(value.store.guard_home), value.connection:
        activation_journal.finish(value.store, value.connection, value.transition, expected_pack=value.pack)
    assert activation_store.read(value.store).metadata == value.prepared.metadata


def test_missing_reservation_cannot_commit_pack_bound_controls(journal):
    value = journal
    with (
        hold_command_control_authority_lock(value.store.guard_home),
        value.connection,
        pytest.raises(NativePolicySnapshotError, match="transition_missing"),
    ):
        activation_journal.finish(value.store, value.connection, value.transition, expected_pack=value.pack)


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
        activation_journal.finish(value.store, value.connection, value.transition, expected_pack=value.pack)


def previous_writer_pending(value):
    """Released writer format: authenticated v1 header and link without floors."""
    import json

    from codex_plugin_scanner.guard.catalog_delivery import activation_record
    from tests.extension_control_records import SNAPSHOT_PURPOSE, anchor_to_json
    from tests.guard_extension_control_authority_fixtures import MemorySecretStore

    with hold_command_control_authority_lock(value.store.guard_home), value.connection:
        reserve(value)
    row = value.connection.execute("select * from extension_command_pack_pending").fetchone()
    header = json.loads(row["record_json"])
    header["schema"] = activation_record.SCHEMA
    header.pop("authority_profile")
    header.pop("authority_schema_version")
    header.pop("purpose")
    data, digest, mac = authenticated_record(header, key=_key(value.store), purpose=activation_record.PURPOSE)
    catalog = header["catalog_digest"]
    old = authenticated_record(dict(revision=0, catalog_digest=catalog), key=b"a" * 32, purpose=SNAPSHOT_PURPOSE)
    next_snapshot = authenticated_record(
        dict(revision=1, catalog_digest=catalog, previous_digest=old[1], command_pack_record_digest=digest),
        key=b"a" * 32,
        purpose=SNAPSHOT_PURPOSE,
    )
    control = authenticated_record(
        dict(
            revision=1,
            previous_revision=0,
            previous_digest=old[1],
            snapshot_digest=next_snapshot[1],
            catalog_digest=catalog,
            phase="prepared",
            command_pack_record_digest=digest,
        ),
        key=b"a" * 32,
        purpose=TRANSITION_PURPOSE,
    )
    link = authenticated_record(
        dict(
            control_revision=1,
            snapshot_digest=next_snapshot[1],
            catalog_digest=catalog,
            pack_record_digest=digest,
            admitted_at=1500,
        ),
        key=_key(value.store),
        purpose=activation_journal.PURPOSE,
    )
    with value.connection:
        value.connection.execute(
            "update extension_command_pack_pending set record_json=?,record_digest=?,record_mac=?,"
            "link_json=?,link_digest=?,link_mac=?",
            (data, digest, mac, *link),
        )
        value.connection.execute(
            "insert into extension_control_authority_snapshot values (1,0,?,'[]',null,?,?,?,'unit')", (catalog, *old)
        )
        value.connection.execute(
            "insert into extension_control_authority_transition values "
            "(1,0,'anchored','a','i','n',?,'[]',?,?,?,?,?,?,'unit',null)",
            (catalog, *next_snapshot, *control),
        )
    value.transition.update(
        snapshot_digest=next_snapshot[1],
        transition_json=control[0],
        transition_digest=control[1],
        transition_mac=control[2],
    )
    value.pack = digest
    value.anchor.current = AuthorityAnchor(1, next_snapshot[1], AuthorityPhase.ANCHORED)
    backend = MemorySecretStore()
    backend.set_secret("anchor", anchor_to_json(value.anchor.current, key=b"a" * 32))
    value.store._secret_store = lambda: backend
    value.store._anchor_ref = lambda: "anchor"
    value.store._policy_integrity_secret_store.values.clear()


def test_previous_writer_pending_migrates_then_resumes_without_reset(journal, release, monkeypatch):
    from codex_plugin_scanner.guard.catalog_delivery import lifecycle_store

    value = journal
    previous_writer_pending(value)
    before = tuple(value.connection.iterdump())
    with hold_command_control_authority_lock(value.store.guard_home):
        lifecycle_store.migrate_installed(value.store, release[0])
    record, floor = lifecycle_store.inspect(value.store)
    assert floor["remote"]["version"] == value.prepared.publication_id
    assert tuple(value.connection.iterdump()) == before
    monkeypatch.setattr("time.time", lambda: 9000000)
    with hold_command_control_authority_lock(value.store.guard_home):
        with pytest.raises(RuntimeError, match="crash"), value.connection:
            activation_journal.finish(value.store, value.connection, value.transition, expected_pack=value.pack)
            raise RuntimeError("crash before SQL commit")
        assert lifecycle_store.read(value.store) == record
        assert activation_store.read(value.store) is None
        with value.connection:
            activation_journal.finish(value.store, value.connection, value.transition, expected_pack=value.pack)
    assert activation_store.read(value.store).metadata == value.prepared.metadata
    assert lifecycle_store.read(value.store) == record
    assert value.connection.execute("select count(*) from extension_command_pack_pending").fetchone()[0] == 0


@pytest.mark.parametrize("damage", ["missing-floor", "corrupt-floor", "snapshot-mac"])
def test_previous_writer_recovery_rejects_damaged_evidence_without_changing_controls(journal, release, damage):
    from codex_plugin_scanner.guard.catalog_delivery import lifecycle_store

    value = journal
    previous_writer_pending(value)
    with hold_command_control_authority_lock(value.store.guard_home):
        lifecycle_store.migrate_installed(value.store, release[0])
    backend = value.store._policy_integrity_secret_store
    reference = value.store._build_scoped_secret_ref(lifecycle_store.PREFIX)
    if damage == "missing-floor":
        backend.delete_secret(reference)
    elif damage == "corrupt-floor":
        backend.set_secret(reference, "corrupt")
    else:
        with value.connection:
            value.connection.execute("update extension_control_authority_snapshot set snapshot_mac=?", ("0" * 64,))
    before = tuple(value.connection.iterdump())
    with (
        hold_command_control_authority_lock(value.store.guard_home),
        value.connection,
        pytest.raises(ValueError, match="pack_lifecycle"),
    ):
        activation_journal.finish(value.store, value.connection, value.transition, expected_pack=value.pack)
    assert tuple(value.connection.iterdump()) == before
    assert activation_store.read(value.store) is None
