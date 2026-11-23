"""Explicitly resume an authenticated prepared source with fresh approval.

This never reconstructs lost state or authorizes a different source. Fresh exact
document approval is mandatory; provider credentials and actors are unrelated.
"""

from datetime import datetime, timezone

from . import native_business_source_store as owner
from .mcp.policy_errors import PolicyToolError
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
    store, document, *, approval_gate_grant, deadline_monotonic=None, recovery_request_id=None
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
        if witness != owner._witness(committed) or recovery_request_id is not None:
            _land_recovery(
                store,
                document,
                owner.BusinessSourceMutation(source, committed),
                witness=witness,
                install=witness != owner._witness(committed),
                recovery_request_id=recovery_request_id,
                approval_gate_grant=approval_gate_grant,
            )
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


def _land_recovery(store, document, mutation, *, witness, install, recovery_request_id, approval_gate_grant):
    """The store's half in one native transaction.

    The resident refuses unless the witness read above is still the stored
    one. It then installs the source when its witness is not yet committed,
    and records the request's recovery marker when a request is named.
    """
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    args = {"now": now, "expected_witness": None if witness is None else witness.decode("utf-8")}
    if install:
        from .business_policy_document_import import approved_install_digest

        digest = approved_install_digest(
            store, document, mutation, mode="replace", now=now, approval_gate_grant=approval_gate_grant
        )
        args.update(store.policy_import_args(document, [], mode="replace", now=now, digest=digest, vault_key=True))
        args["business_witness"] = mutation.witness_text()
    if recovery_request_id is not None:
        args["recovery_request"] = {"request_id": recovery_request_id, "source_digest": mutation.source.source_digest}
    try:
        payload = store._native_store_call("recover_business_policy_source", args)
    except ValueError as error:
        if str(error) == "candidate_digest_mismatch":
            raise PolicyToolError(
                "candidate_digest_mismatch", "The stored request changed. Refresh before recovery."
            ) from None
        if str(error) == "native_business_source_current_digest_changed":
            raise owner._error("native_business_source_current_digest_changed") from None
        raise
    if not isinstance(payload, dict):
        raise owner._error()
    store.finalize_policy_import(payload.get("next_control_state"))
