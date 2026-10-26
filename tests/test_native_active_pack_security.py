"""Stateful compiled native security with isolated SQLite/credential transports.

Synthetic pack IR qualifies observation, proof and persistence boundaries;
native matcher/quarantine tests separately exercise executable compiler output.
"""

from __future__ import annotations

import copy
import sqlite3
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import (
    activation_record,
    activation_store,
    active_security,
    preparation,
)
from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import ObjectStore
from codex_plugin_scanner.guard.catalog_delivery.pack_store import PackReader
from codex_plugin_scanner.guard.native_command_control_authority_io import hold_command_control_authority_lock
from codex_plugin_scanner.guard.native_command_control_authority_store import _key
from codex_plugin_scanner.guard.store_extension_control_authority_schema import (
    ensure_extension_control_authority_schema,
)
from tests.delivery_scripts import script
from tests.native_activation_support import compiled_lifecycle as compiled_lifecycle
from tests.native_activation_support import seed
from tests.test_extension_pack_preparation import delivery as delivery

revocation_key = script("extension_delivery_revocations").revocation_key


@pytest.fixture
def device(delivery):
    store = SimpleNamespace(guard_home=delivery.cache.parent / "device")
    store.guard_home.mkdir(mode=0o700)
    seed(store)
    store._extension_control_authority_lock = lambda: hold_command_control_authority_lock(store.guard_home)

    def connect():
        connection = sqlite3.connect(store.guard_home / "guard.db")
        connection.row_factory = sqlite3.Row
        return connection

    store._connect = connect
    prepared = preparation.prepare(
        delivery.verified(),
        [],
        activation_store.prepare_directory_for_store(store),
        engine="1" * 64,
        now=1500,
        fetch=delivery.fetch,
    )
    data, digest, mac = activation_record.seal(prepared, key=_key(store), revision=1, now=1500)
    with connect() as connection:
        ensure_extension_control_authority_schema(connection, activate_packs=True, activation_format_v2=True)
        connection.execute(
            "insert into extension_command_pack_activation values (1,1,?,?,?,'fixture')", (data, digest, mac)
        )
        # Actual durable table shape used by saved exact-action decisions.
        connection.execute(
            "create table policy_decisions(decision_id integer primary key,artifact_hash text,action text)"
        )
        connection.execute("insert into policy_decisions values(1,'retained-exact-action','allow')")
    return store


def publication(delivery, identity="command.core", *, kind="pack", epoch=1, state="revoked"):
    root = copy.deepcopy(delivery.value)
    root["publication_id"] = f"12.{epoch + 1}"
    manifest = delivery.manifests[identity]["sha256"] if kind == "pack" else None
    record = dict(
        schema="guard.extension-revocation.v1",
        extension_id=identity,
        kind=kind,
        epoch=epoch,
        state=state,
        reason="Reviewed security change.",
    )
    if manifest is not None:
        record["manifest_sha256"] = manifest
    reference = delivery.store.put_json(record)
    root["policy"]["revocations"] = dict(
        epoch=epoch, count=1, index=delivery.store.index({revocation_key(identity, kind, manifest): reference})
    )
    delivery.plan.finish()
    return delivery.verified(root)


def observe(device, authority, delivery):
    active_security._observe_capability(
        device, active_security.read(device), active_security._activation(device), authority, delivery.fetch
    )
    record = active_security.read(device)
    return active_security.invoke("read", device, record=record)


@pytest.mark.parametrize("kind", ["pack", "extension"])
def test_known_active_revocation_survives_restart_outage_and_sqlite_loss(device, delivery, kind, monkeypatch):
    result = observe(device, publication(delivery, kind=kind), delivery)
    assert result["quarantine"] == ["command.core"] and not result["pending"]
    record = active_security.read(device)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.catalog_delivery.preparation_authority.load_installed_bundle", lambda: None
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.catalog_delivery.transport.fetch_root",
        lambda **kwargs: (_ for _ in ()).throw(OSError("offline")),
    )
    active_security.observe(device)
    active_security.reconcile(device)
    assert active_security.read(device) == record
    with device._connect() as connection:
        assert tuple(connection.execute("select * from policy_decisions").fetchone()) == (
            1,
            "retained-exact-action",
            "allow",
        )
    (device.guard_home / "guard.db").unlink()
    with pytest.raises(ValueError, match="activation_missing"):
        active_security.reconcile(device)
    assert active_security.read(device) == record


def test_reconcile_keeps_matching_private_file_stable_and_restores_missing_file(device, delivery, monkeypatch):
    observe(device, delivery.verified(), delivery)
    path = device.guard_home / "native-runtime" / active_security.FILE
    before = path.stat()
    data = path.read_bytes()

    def unexpected_exclusive():
        pytest.fail("matching private state must coexist with native shared readers")

    with monkeypatch.context() as patches:
        patches.setattr(device, "_extension_control_authority_lock", unexpected_exclusive)
        active_security.reconcile(device)
    after = path.stat()
    assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
    path.unlink()
    active_security.reconcile(device)
    assert path.read_bytes() == data


def test_inactive_revocation_preserves_applicable_identity_and_allow_rows(device, delivery, monkeypatch):
    def unexpected_fence(*args, **kwargs):
        pytest.fail("inactive security must not rewrite the decision/approval marker")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_command_control_authority_store.begin_native_command_control_mutation",
        unexpected_fence,
    )
    first = observe(device, delivery.verified(), delivery)
    second = observe(device, publication(delivery, "command.unused"), delivery)
    assert first["applicable_digest"] is None and second["applicable_digest"] is None
    assert second["quarantine"] == []
    with device._connect() as connection:
        assert connection.execute("select action from policy_decisions").fetchone()[0] == "allow"


def test_lower_epoch_and_same_epoch_substitution_reject(device, delivery):
    authority = publication(delivery, epoch=2)
    result = observe(device, authority, delivery)
    with pytest.raises(ValueError, match="epoch_rollback"):
        observe(device, delivery.verified(), delivery)
    with pytest.raises(ValueError, match="epoch_reused"):
        observe(device, publication(delivery, "command.unused", epoch=2), delivery)
    assert active_security.invoke("read", device, record=active_security.read(device)) == result


@pytest.mark.parametrize("failure", ["missing", "corrupt", "substituted"])
def test_known_newer_epoch_with_unavailable_proof_is_durable_pending(device, delivery, failure):
    authority = publication(delivery)
    fetch = delivery.fetch

    def broken(target, maximum):
        if failure == "missing":
            raise OSError("unavailable proof")
        value = fetch(target, maximum)
        return b"invalid" if failure == "corrupt" else value[::-1]

    with pytest.raises((ValueError, OSError)):
        active_security._observe_capability(device, None, active_security._activation(device), authority, broken)
    record = active_security.read(device)
    assert active_security.invoke("read", device, record=record)["pending"]
    active_security.reconcile(device)  # Published pending remains terminal, with no network.
    assert active_security.read(device) == record
    complete = observe(device, authority, delivery)
    assert complete["quarantine"] == ["command.core"] and not complete["pending"]


def test_absence_does_not_restore_known_revocation_and_explicit_restore_rebinds(device, delivery):
    first = observe(device, publication(delivery), delivery)
    root = copy.deepcopy(delivery.value)
    root["policy"]["revocations"]["epoch"] = 2
    root["publication_id"] = "12.3"
    absent = observe(device, delivery.verified(root), delivery)
    assert absent["quarantine"] == ["command.core"]
    restored = observe(device, publication(delivery, epoch=3, state="restored"), delivery)
    assert restored["quarantine"] == []
    assert restored["applicable_digest"] not in (None, first["applicable_digest"])


def test_concurrent_observation_cas_rejects_stale_completion(device, delivery):
    activation = active_security._activation(device)
    older = active_security._prepare(
        device, None, activation, publication(delivery).data.decode(), delivery.fetch, profile="remote"
    )
    newer = publication(delivery, epoch=2)
    result = observe(device, newer, delivery)
    with pytest.raises(ValueError, match="observation_conflict"):
        active_security._commit(device, None, activation, older)
    assert active_security.invoke("read", device, record=active_security.read(device)) == result


def test_corrupt_or_missing_protected_record_cannot_be_recreated_from_sqlite(device, delivery):
    observe(device, publication(delivery), delivery)
    backend = device._policy_integrity_secret_store
    reference = device._build_scoped_secret_ref(active_security.PREFIX)
    backend.set_secret(reference, "corrupt")
    with pytest.raises(ValueError):
        active_security.reconcile(device)
    backend.delete_secret(reference)
    with pytest.raises(ValueError, match="protected_record_missing"):
        active_security.reconcile(device)


def test_new_trust_quarantines_active_and_verified_replacement_clears_offline(device, delivery):
    observe(device, delivery.verified(), delivery)
    directory = activation_store.directory_for_store(device)
    local = ObjectStore(directory / "objects")
    old = PackReader(directory / "objects").json(delivery.manifests["command.core"])
    replacement = local.put_json({**old, "trust_digest": "9" * 64})
    manifests = {**delivery.manifests, "command.core": replacement}
    index = local.index(manifests)
    wrapper = delivery.store.json(delivery.value["policy"]["transport"])
    rows = []
    for identity, reference in wrapper["records"]:
        if identity == "command.core":
            metadata = delivery.store.json(reference)
            reference = delivery.store.put_json({**metadata, "manifest": replacement})
        rows.append([identity, reference])
    native = delivery.store.put(PackReader(directory / "objects").blob(index))
    transport = delivery.store.put_json({**wrapper, "native": native, "records": rows})
    root = copy.deepcopy(delivery.value)
    root["publication_id"] = "12.2"
    root["policy"]["root"]["index"] = index
    root["policy"]["transport"] = transport
    core_record = next(reference for identity, reference in rows if identity == "command.core")
    root["policy"]["defaults"] = dict(count=1, index=delivery.store.index({"command.core": core_record}))
    delivery.plan.finish()
    authority = delivery.verified(root)
    result = observe(device, authority, delivery)
    assert result["quarantine"] == ["command.core"]
    with pytest.raises(ValueError, match="version_rollback"):
        observe(device, delivery.verified(), delivery)
    # The activation adapter seals the replacement's complete prepared identity;
    # the observer then derives the new active selection from that MAC, offline.
    previous = active_security._activation(device)
    prepared = preparation.prepare(authority, [], directory, engine="1" * 64, now=1500, fetch=delivery.fetch)
    data, digest, mac = activation_record.seal(
        prepared, key=_key(device), revision=2, previous_digest=previous["activation_digest"], now=1500
    )
    with device._connect() as connection:
        connection.execute(
            "update extension_command_pack_activation set revision=2,record_json=?,record_digest=?,record_mac=?",
            (data, digest, mac),
        )
    active_security.reconcile(device)
    result = active_security.invoke("read", device, record=active_security.read(device))
    assert result["quarantine"] == [] and result["applicable_digest"] is None


@pytest.mark.parametrize("field", ["activation", "activation_digest", "activation_mac"])
def test_untrusted_active_identity_cannot_select_security_scope(device, delivery, field):
    activation = active_security._activation(device)
    activation[field] = "substituted"
    with pytest.raises(ValueError, match=r"activation_invalid|authentication_failed"):
        active_security.invoke(
            "begin",
            device,
            record=None,
            publication=publication(delivery).data.decode(),
            profile="remote",
            lineage_floor="irrelevant",
            **activation,
        )
    assert active_security.read(device) is None


@pytest.mark.parametrize("floor", ["authority", "engine"])
def test_applicable_native_minimum_and_engine_floor_quarantine(device, delivery, floor):
    root = copy.deepcopy(delivery.value)
    root["publication_id"] = "12.2"
    if floor == "authority":
        root["authority_epoch"] = 2
    else:
        root["engine"] = "2" * 64
        root["policy"]["root"]["engine"] = "2" * 64
    result = observe(device, delivery.verified(root), delivery)
    assert result["quarantine"] == ["command.core"] and result["applicable_digest"] is not None


def test_security_fetches_never_hold_the_mutation_lease(device, delivery):
    from codex_plugin_scanner.guard.native_command_control_authority_io import (
        require_exclusive_command_control_mutation_lease,
    )
    from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError

    calls = []

    def fetch(target, maximum):
        with pytest.raises(NativePolicySnapshotError, match="lease_missing"):
            require_exclusive_command_control_mutation_lease(device.guard_home)
        calls.append(target)
        return delivery.fetch(target, maximum)

    active_security._observe_capability(device, None, active_security._activation(device), publication(delivery), fetch)
    assert calls


def test_protected_write_requires_readback(device, delivery, monkeypatch):
    monkeypatch.setattr(device._policy_integrity_secret_store, "set_secret", lambda *args: None)
    with pytest.raises(ValueError, match="protected_write_mismatch"):
        observe(device, publication(delivery), delivery)
