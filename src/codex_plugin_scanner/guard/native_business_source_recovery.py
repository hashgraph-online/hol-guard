"""Explicitly resume an authenticated prepared source with fresh approval.

This never reconstructs lost state or authorizes a different source. Fresh exact
document approval is mandatory; provider credentials and actors are unrelated.
"""

from datetime import datetime, timezone

from . import native_business_source_store as owner
from .native_business_source_anchor_bridge import build_business_source_anchor, verify_business_source_anchor
from .native_business_source_bridge import _consumer, _deadline, _remaining, verify_business_source_record
from .native_business_source_retention import (
    read_retained_business_source_anchor_copies,
    write_retained_business_source_anchor,
)
from .native_command_control_authority_io import hold_command_control_authority_lock, read_private_state
from .native_policy_snapshot_codec import derive_native_policy_verifier_key
from .policy_document import policy_document_digest
from .policy_document_authority import policy_import_approval_binding


def recover_committed_business_source(
    store, document, *, approval_gate_grant, deadline_monotonic=None, stage_request_recovery=None
):
    """Finish the exact prepared document, never restore an older source or replay work."""
    deadline = _deadline(deadline_monotonic)
    status = _consumer(deadline, anchor=True)
    if status.capabilities is None or owner.CURRENT_FENCE_CAPABILITY not in status.capabilities.features:
        raise owner._error("native_business_source_current_fence_unavailable")
    binding = policy_import_approval_binding(document, "replace")

    def require_approval():
        owner._require_approved(
            store, binding, approval_gate_grant, datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )

    require_approval()
    with hold_command_control_authority_lock(store.guard_home, timeout_seconds=_remaining(deadline)):
        require_approval()
        material = store._policy_integrity_secret_material(create=False)
        if material is None or type(material[0]) is not bytes or len(material[0]) != 32:
            raise owner._error("native_business_source_installation_key_unavailable")
        key = derive_native_policy_verifier_key(material[0])
        prepared = read_private_state(store.guard_home, owner.PREPARED_SOURCE_FILE_NAME, owner.MAX_RECORD_BYTES)
        record = read_private_state(store.guard_home, owner.SOURCE_FILE_NAME, owner.MAX_RECORD_BYTES)
        marker = read_private_state(store.guard_home, owner.ANCHOR_FILE_NAME, owner.MAX_ANCHOR_BYTES)
        copies = read_retained_business_source_anchor_copies(store)
        candidate = prepared if prepared is not None else record
        if candidate is None:
            raise owner._error("native_business_source_recovery_required")
        source = verify_business_source_record(candidate, key, deadline_monotonic=deadline)
        if source.source_digest != policy_document_digest(document):
            raise owner._error("native_business_source_recovery_identity_mismatch")
        # Every readable authenticated floor must permit this exact candidate.
        # No majority, fallback selection or silent repair of unavailable copies.
        for wire in (marker, *copies):
            if wire is not None:
                anchor = verify_business_source_anchor(wire, key, deadline_monotonic=deadline)
                verify_business_source_record(
                    candidate, key, deadline_monotonic=deadline, retained_identity_bytes=anchor.retained_identity_bytes
                )
        witness = owner._database_witness(store)
        anchors = (marker, *copies)
        if witness is None:
            owner._refuse_native_business_floor_without_source(store, key)
        else:
            if all(wire is None for wire in anchors) or any(wire is None for wire in copies):
                raise owner._error("native_business_source_recovery_required")
            # SQL may retain a newer identity even when readable markers were
            # rolled back. Its floor can only restrict this recovery candidate.
            from .native_policy_snapshot_codec import _canonical_json_bytes_v3, _strict_json_loads_v3

            observed = _strict_json_loads_v3(witness)
            if (
                not isinstance(observed, dict)
                or observed.get("schema") != "guard.business-source-installation.v1"
                or "retained_identity" not in observed
            ):
                raise owner._error("native_business_source_recovery_required")
            verify_business_source_record(
                candidate,
                key,
                deadline_monotonic=deadline,
                retained_identity_bytes=_canonical_json_bytes_v3(observed["retained_identity"]),
            )
        closed = build_business_source_anchor(source, key, "closed", deadline_monotonic=deadline)
        committed = build_business_source_anchor(source, key, "committed", deadline_monotonic=deadline)
        # Old installations without a prepared record retain the narrow existing
        # committed-witness recovery contract; incomplete history is not rebuilt.
        if prepared is None and (marker != closed.anchor_bytes or witness != owner._witness(committed)):
            raise owner._error("native_business_source_recovery_required")
        require_approval()
        owner._write_private(store, owner.ANCHOR_FILE_NAME, closed.anchor_bytes, owner.MAX_ANCHOR_BYTES, deadline)
        write_retained_business_source_anchor(store, closed.anchor_bytes)
        owner._write_private(store, owner.SOURCE_FILE_NAME, candidate, owner.MAX_RECORD_BYTES, deadline)
        if witness != owner._witness(committed) or stage_request_recovery is not None:
            from .business_policy_document_import import apply_business_document_on_connection

            with store._connect() as connection:
                connection.execute("begin immediate")
                if owner._read_witness(connection) != witness:
                    raise owner._error("native_business_source_current_digest_changed")
                now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                if witness != owner._witness(committed):
                    apply_business_document_on_connection(
                        store,
                        document,
                        owner.BusinessSourceMutation(source, committed),
                        mode="replace",
                        now=now,
                        approval_gate_grant=approval_gate_grant,
                        connection=connection,
                    )
                if stage_request_recovery is not None:
                    stage_request_recovery(connection, source.source_digest, now)
                connection.commit()
        if owner._database_witness(store) != owner._witness(committed):
            raise owner._error("native_business_source_transaction_not_committed")
        if (
            read_private_state(store.guard_home, owner.SOURCE_FILE_NAME, owner.MAX_RECORD_BYTES) != candidate
            or read_private_state(store.guard_home, owner.ANCHOR_FILE_NAME, owner.MAX_ANCHOR_BYTES)
            != closed.anchor_bytes
            or any(value != closed.anchor_bytes for value in read_retained_business_source_anchor_copies(store))
        ):
            raise owner._error()
        require_approval()
        write_retained_business_source_anchor(store, committed.anchor_bytes)
        owner._write_private(store, owner.ANCHOR_FILE_NAME, committed.anchor_bytes, owner.MAX_ANCHOR_BYTES, deadline)
        return source
