"""Bind prepared packs to the existing authenticated two-phase control commit."""

from __future__ import annotations

import time

from ..native_command_control_authority_io import require_exclusive_command_control_mutation_lease
from ..native_command_control_authority_store import _key
from ..native_policy_snapshot_constants import NativePolicySnapshotError
from ..runtime.extension_control_authority import (
    TRANSITION_PURPOSE,
    ExtensionControlAuthorityError,
    authenticated_record,
    verify_authenticated_record,
)
from . import activation_baseline, lifecycle_store
from .activation_record import SCHEMA_V2, admission_is_current, verify_header
from .activation_store import _row, directory_for_store, write_in_transaction
from .activation_transition import ActivationDraft

PURPOSE = "command-pack-control-transition.v1"


class UnverifiablePackTransitionError(NativePolicySnapshotError):
    """Pending pack bytes cannot authenticate against their approved transition."""


def _exists(connection):
    return (
        connection.execute(
            "select 1 from sqlite_master where type='table' and name='extension_command_pack_pending'"
        ).fetchone()
        is not None
    )


def reserve(store, connection, draft, *, control_revision, snapshot_digest, catalog_digest, recorded_at, now=None):
    """Reserve with PREPARED controls, before the private anchor is advanced."""
    require_exclusive_command_control_mutation_lease(store.guard_home)
    if type(draft) is not ActivationDraft or draft.directory != directory_for_store(store):
        raise NativePolicySnapshotError("native_command_pack_draft_invalid")
    key = _key(store)
    lifecycle_store.check(store, draft.lifecycle_before, draft.lifecycle_after)
    from .active_security import check_scope

    check_scope(store, draft.security_digest)
    header = verify_header(draft.data, draft.digest, draft.mac, key=key)
    admitted_at = int(time.time()) if now is None else now
    if (
        type(admitted_at) is not int
        or not admission_is_current(header, admitted_at)
        or header["catalog_digest"] != catalog_digest
    ):
        raise NativePolicySnapshotError("native_command_pack_draft_invalid")
    if draft.previous_digest is None:
        if draft.baseline_metadata is None:
            raise NativePolicySnapshotError("native_command_pack_baseline_missing")
        activation_baseline.reserve_legacy_baseline(
            store, connection, draft.baseline_metadata, key=key, recorded_at=recorded_at
        )
    from ..store_extension_control_authority_schema import ensure_extension_control_authority_schema

    ensure_extension_control_authority_schema(
        connection, activate_packs=True, activation_format_v2=header["schema"] == SCHEMA_V2
    )
    current = _row(connection)
    if current is None:
        raise NativePolicySnapshotError("native_command_pack_activation_missing")
    if activation_baseline.is_baseline(current["record_json"]):
        activation_baseline.verify(current, key)
        previous_digest = None
    else:
        previous = verify_header(current["record_json"], current["record_digest"], current["record_mac"], key=key)
        if previous["revision"] != current["revision"]:
            raise NativePolicySnapshotError("native_command_pack_revision_invalid")
        previous_digest = current["record_digest"]
    if previous_digest != draft.previous_digest or header["previous_digest"] != previous_digest:
        raise NativePolicySnapshotError("native_command_pack_activation_conflict")
    if connection.execute(
        "select 1 from extension_command_pack_pending where control_revision=?", (control_revision,)
    ).fetchone():
        raise NativePolicySnapshotError("native_command_pack_reservation_conflict")
    # The link is authenticated separately from both the data and control
    # records. Copying a draft to another approved transition cannot reuse it.
    data, digest, mac = authenticated_record(
        {
            "control_revision": control_revision,
            "snapshot_digest": snapshot_digest,
            "catalog_digest": catalog_digest,
            "pack_record_digest": draft.digest,
            "admitted_at": admitted_at,
            "lifecycle_before": draft.lifecycle_before,
            "lifecycle_after": draft.lifecycle_after,
            **({"security_digest": draft.security_digest} if draft.security_digest is not None else {}),
        },
        key=key,
        purpose=PURPOSE,
    )
    connection.execute(
        "insert into extension_command_pack_pending values (?,?,?,?,?,?,?)",
        (control_revision, draft.data, draft.digest, draft.mac, data, digest, mac),
    )


def finish(store, connection, transition):
    """Install packs in the same transaction as the anchored control snapshot.

    A recovered anchored transition was approved and admitted while fresh.
    It may finish offline after expiry, just as an already committed active
    snapshot remains usable offline. Unanchored reservations grant no authority.
    """
    authority_key = store._authority_key(required=True)
    control = verify_authenticated_record(
        transition["transition_json"],
        expected_digest=transition["transition_digest"],
        expected_mac=transition["transition_mac"],
        key=authority_key,
        purpose=TRANSITION_PURPOSE,
    )
    expected_pack = control.get("command_pack_record_digest")
    row = (
        None
        if not _exists(connection)
        else connection.execute(
            "select * from extension_command_pack_pending where control_revision=?", (transition["revision"],)
        ).fetchone()
    )
    if expected_pack is None and row is None:
        return
    require_exclusive_command_control_mutation_lease(store.guard_home)
    if row is None or row["record_digest"] != expected_pack:
        raise UnverifiablePackTransitionError("native_command_pack_transition_missing")
    anchor = store._read_anchor(key=authority_key)
    if (
        anchor is None
        or anchor.revision != transition["revision"]
        or anchor.snapshot_digest != transition["snapshot_digest"]
        or anchor.phase.value not in {"anchored", "committed"}
    ):
        raise NativePolicySnapshotError("native_command_pack_transition_unanchored")
    key = _key(store)
    header, link = _verified_pending(row, transition, key)
    if "lifecycle_before" not in link:
        from . import lifecycle

        link.update(
            lifecycle.invoke(
                "legacy-pending",
                key=key.hex(),
                floor=lifecycle_store.read(store),
                **lifecycle_store.legacy_evidence(store, connection),
            )
        )
    draft = object.__new__(ActivationDraft)
    for name, value in {
        "directory": directory_for_store(store),
        "data": row["record_json"],
        "digest": row["record_digest"],
        "mac": row["record_mac"],
        "previous_digest": header["previous_digest"],
        "baseline_metadata": None,
        "lifecycle_before": link["lifecycle_before"],
        "lifecycle_after": link["lifecycle_after"],
        "security_digest": link.get("security_digest"),
    }.items():
        object.__setattr__(draft, name, value)
    write_in_transaction(
        store, connection, draft, verifier_key=key, recorded_at=transition["created_at"], now=link["admitted_at"]
    )
    connection.execute("delete from extension_command_pack_pending where control_revision=?", (transition["revision"],))


def _verified_pending(row, transition, key):
    # Only bounded, pure authentication failures are eligible for an explicit
    # recovery reset. Key access, lineage checks and storage errors stay retryable.
    try:
        return _verify_pending(row, transition, key)
    except (ExtensionControlAuthorityError, ValueError) as error:
        raise UnverifiablePackTransitionError("native_command_pack_transition_mismatch") from error


def _verify_pending(row, transition, key):
    link = verify_authenticated_record(
        row["link_json"], expected_digest=row["link_digest"], expected_mac=row["link_mac"], key=key, purpose=PURPOSE
    )
    expected = {
        "control_revision": transition["revision"],
        "snapshot_digest": transition["snapshot_digest"],
        "catalog_digest": transition["catalog_digest"],
        "pack_record_digest": row["record_digest"],
    }
    lifecycle_fields = {"lifecycle_before", "lifecycle_after"} if "lifecycle_before" in link else set()
    if set(link) != {
        "authority_schema_version",
        "purpose",
        "admitted_at",
        *lifecycle_fields,
        *({"security_digest"} if "security_digest" in link else set()),
        *expected,
    } or any(link[name] != value for name, value in expected.items()):
        raise UnverifiablePackTransitionError("native_command_pack_transition_mismatch")
    header = verify_header(row["record_json"], row["record_digest"], row["record_mac"], key=key)
    if header["catalog_digest"] != transition["catalog_digest"]:
        raise UnverifiablePackTransitionError("native_command_pack_transition_mismatch")
    return header, link


def abandon(connection, revision):
    """An unanchored reservation never changes the active slot."""
    if _exists(connection):
        connection.execute("delete from extension_command_pack_pending where control_revision=?", (revision,))


def abandon_all(connection, *, archive_id=None):
    """Reset archives reservations and discards them with their transitions."""
    if _exists(connection):
        if archive_id is not None:
            import json

            rows = connection.execute(
                "select * from extension_command_pack_pending order by control_revision"
            ).fetchall()
            connection.execute(
                "insert into extension_control_pack_reservation_archive values (?,?)",
                (archive_id, json.dumps([dict(row) for row in rows], sort_keys=True, separators=(",", ":"))),
            )
        connection.execute("delete from extension_command_pack_pending")
