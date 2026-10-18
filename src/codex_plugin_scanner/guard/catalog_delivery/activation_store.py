"""Protected activation slot. Callers own approval and the SQL transaction."""

from __future__ import annotations

import time

from ..native_command_control_authority_io import require_exclusive_command_control_mutation_lease
from ..native_policy_snapshot_constants import NATIVE_RUNTIME_STATE_DIRECTORY, NativePolicySnapshotError
from ..store_extension_control_authority_schema import (
    PACK_ACTIVATION_SCHEMA_VERSION,
    ensure_extension_control_authority_schema,
    extension_control_schema_marker_is_compatible,
)
from . import activation_baseline
from .activation_record import open_record, verify_header
from .activation_transition import ActivationDraft


def directory_for_store(store):
    return store.guard_home / NATIVE_RUNTIME_STATE_DIRECTORY / "command-packs"


def prepare_directory_for_store(store):
    """Provision the private native state parent before creating pack caches."""
    from ..native_policy_snapshot_windows_support import _runtime_state_directory

    return _runtime_state_directory(store.guard_home) / "command-packs"


def _row(connection):
    marker = connection.execute(
        "select version, checksum from extension_control_schema_migration where singleton=1"
    ).fetchone()
    if marker is None or not extension_control_schema_marker_is_compatible(marker["version"], marker["checksum"]):
        raise NativePolicySnapshotError("native_command_pack_schema_invalid")
    if marker["version"] < PACK_ACTIVATION_SCHEMA_VERSION:
        return None
    value = connection.execute("""select * from extension_command_pack_activation where singleton=1
        and length(cast(record_json as blob)) between 1 and 65536
        and length(record_digest)=64 and length(record_mac)=64""").fetchone()
    if value is None:
        raise NativePolicySnapshotError("native_command_pack_activation_missing")
    return value


def read(store):
    """Authenticate outside mutation locks; this may read cached metadata pages."""
    with store._connect() as connection:
        if not connection.execute(
            "select 1 from sqlite_master where type='table' and name='extension_control_schema_migration'"
        ).fetchone():
            return None
        row = _row(connection)
    if row is None:
        return None
    from ..native_command_control_authority_store import _key

    if activation_baseline.is_baseline(row["record_json"]):
        activation_baseline.verify(row, _key(store))
        return None
    result = open_record(
        row["record_json"],
        row["record_digest"],
        row["record_mac"],
        key=_key(store),
        directory=directory_for_store(store),
    )
    if result.record()["revision"] != row["revision"]:
        raise NativePolicySnapshotError("native_command_pack_revision_invalid")
    return result


def header_for_store(store, verifier_key):
    """Small authenticated recheck; never materialize a catalog under a lease."""
    with store._connect() as connection:
        if not connection.execute(
            "select 1 from sqlite_master where type='table' and name='extension_control_schema_migration'"
        ).fetchone():
            return None
        row = _row(connection)
    if row is None:
        return None
    if activation_baseline.is_baseline(row["record_json"]):
        return activation_baseline.verify(row, verifier_key)
    value = verify_header(row["record_json"], row["record_digest"], row["record_mac"], key=verifier_key)
    if value["revision"] != row["revision"]:
        raise NativePolicySnapshotError("native_command_pack_revision_invalid")
    return value


def write_in_transaction(store, connection, draft, *, verifier_key, recorded_at, now=None):
    """Commit with controls after external preparation and lineage checks.

    No source/network lookup or large metadata reconstruction occurs here.
    The outer control transition must commit this connection atomically.
    """
    require_exclusive_command_control_mutation_lease(store.guard_home)
    if type(draft) is not ActivationDraft or draft.directory != directory_for_store(store):
        raise NativePolicySnapshotError("native_command_pack_draft_invalid")
    header = verify_header(draft.data, draft.digest, draft.mac, key=verifier_key)
    now = int(time.time()) if now is None else now
    if type(now) is not int or not header["issued_at"] <= now < header["expires_at"]:
        raise NativePolicySnapshotError("native_command_pack_draft_expired")
    ensure_extension_control_authority_schema(connection)
    current = _row(connection)
    if current is not None and activation_baseline.is_baseline(current["record_json"]):
        activation_baseline.verify(current, verifier_key)
        current = None
    digest = None if current is None else current["record_digest"]
    if digest != draft.previous_digest or header["previous_digest"] != digest:
        raise NativePolicySnapshotError("native_command_pack_activation_conflict")
    revision = 1
    if current is not None:
        previous = verify_header(
            current["record_json"], current["record_digest"], current["record_mac"], key=verifier_key
        )
        revision = previous["revision"] + 1
        if (
            header["authority_epoch"] < previous["authority_epoch"]
            or header["revocation_epoch"] < previous["revocation_epoch"]
        ):
            raise NativePolicySnapshotError("native_command_pack_epoch_rollback")
        old_publication = tuple(map(int, previous["publication_id"].split(".")))
        new_publication = tuple(map(int, header["publication_id"].split(".")))
        if new_publication < old_publication or (
            new_publication == old_publication and header["root_digest"] != previous["root_digest"]
        ):
            raise NativePolicySnapshotError("native_command_pack_publication_rollback")
    if header["revision"] != revision:
        raise NativePolicySnapshotError("native_command_pack_revision_invalid")
    ensure_extension_control_authority_schema(connection, activate_packs=True)
    connection.execute(
        """insert into extension_command_pack_activation
        (singleton,revision,record_json,record_digest,record_mac,recorded_at) values (1,?,?,?,?,?)
        on conflict(singleton) do update set revision=excluded.revision, record_json=excluded.record_json,
        record_digest=excluded.record_digest,record_mac=excluded.record_mac,recorded_at=excluded.recorded_at""",
        (revision, draft.data, draft.digest, draft.mac, recorded_at),
    )
    return draft.digest
