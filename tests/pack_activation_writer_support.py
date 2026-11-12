"""The pack activation write the resident now owns, kept for test fixtures.

Production writes the activation slot through the resident's ``pack_finish``
op. Tests that need an activation row on disk without a resident build it
here.
"""

from __future__ import annotations

import time

from codex_plugin_scanner.guard.catalog_delivery import (
    activation_baseline,
    activation_store,
    lifecycle,
    lifecycle_store,
)
from codex_plugin_scanner.guard.catalog_delivery.activation_record import SCHEMA_V2, admission_is_current, verify_header
from codex_plugin_scanner.guard.catalog_delivery.activation_transition import ActivationDraft
from codex_plugin_scanner.guard.catalog_delivery.active_security import check_scope
from codex_plugin_scanner.guard.native_command_control_authority_io import (
    require_exclusive_command_control_mutation_lease,
)
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.store_extension_control_authority_schema import (
    ensure_extension_control_authority_schema,
)


@lifecycle.one_runtime
def write_in_transaction(store, connection, draft, *, verifier_key, recorded_at, now=None):
    """Commit with controls after external preparation and lineage checks.

    No source/network lookup or large metadata reconstruction occurs here.
    The outer control transition must commit this connection atomically.
    """
    require_exclusive_command_control_mutation_lease(store.guard_home)
    if type(draft) is not ActivationDraft or draft.directory != activation_store.directory_for_store(store):
        raise NativePolicySnapshotError("native_command_pack_draft_invalid")
    header = verify_header(draft.data, draft.digest, draft.mac, key=verifier_key)
    now = int(time.time()) if now is None else now
    if type(now) is not int or not admission_is_current(header, now):
        raise NativePolicySnapshotError("native_command_pack_draft_expired")
    ensure_extension_control_authority_schema(connection)
    current = activation_store._row(connection)
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
    if header["revision"] != revision:
        raise NativePolicySnapshotError("native_command_pack_revision_invalid")
    check_scope(store, draft.security_digest)
    lifecycle_store.commit(store, draft.lifecycle_before, draft.lifecycle_after)
    ensure_extension_control_authority_schema(
        connection, activate_packs=True, activation_format_v2=header["schema"] == SCHEMA_V2
    )
    connection.execute(
        """insert into extension_command_pack_activation
        (singleton,revision,record_json,record_digest,record_mac,recorded_at) values (1,?,?,?,?,?)
        on conflict(singleton) do update set revision=excluded.revision, record_json=excluded.record_json,
        record_digest=excluded.record_digest,record_mac=excluded.record_mac,recorded_at=excluded.recorded_at""",
        (revision, draft.data, draft.digest, draft.mac, recorded_at),
    )
    return draft.digest
