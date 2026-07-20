"""Authenticated workflow-capability authority persistence validation."""

# pyright: reportAny=false, reportUnusedCallResult=false

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace

from .store_workflow_capability_transitions import validate_capability_transition_projection
from .workflow_capabilities import (
    SignedWorkflowCapability,
    SignedWorkflowCapabilityReceipt,
    WorkflowCapabilityError,
    WorkflowCapabilityReceipt,
    canonical_framed_payload,
    parse_utc_timestamp,
    verify_workflow_capability_receipt,
    workflow_capability_claim_sha256,
)
from .workflow_capability_authority_state import (
    AUTHORITY_STATE_SCHEMA,
    REVOCATION_SCHEMA,
    SignedAuthorityState,
    WorkflowCapabilityAuthorityState,
    WorkflowCapabilityRevocation,
    decode_signed_authority_state,
    decode_signed_revocation,
    encode_signed_authority_state,
    encode_signed_revocation,
    sign_authority_state,
    sign_revocation,
    verify_authority_state,
    verify_revocation,
)


def create_authority_state(
    connection: sqlite3.Connection,
    signed_claim: SignedWorkflowCapability,
    *,
    key: bytes,
    key_id: str,
    now: str,
) -> SignedAuthorityState:
    state = WorkflowCapabilityAuthorityState(
        schema_version=AUTHORITY_STATE_SCHEMA,
        capability_id=signed_claim.claim.capability_id,
        claim_sha256=workflow_capability_claim_sha256(signed_claim),
        use_high_water=0,
        observed_at=now,
        revision=0,
        revocation_id=None,
        revoked_at=None,
    )
    signed_state = sign_authority_state(state, key=key, key_id=key_id)
    _write_state(connection, signed_state, insert=True)
    return signed_state


def load_and_validate_authority(
    connection: sqlite3.Connection,
    signed_claim: SignedWorkflowCapability,
    *,
    key: bytes,
    key_id: str,
    used_count: int,
    revoked_at: object,
    revocation_code: object,
) -> WorkflowCapabilityAuthorityState:
    capability_id = signed_claim.claim.capability_id
    row = connection.execute(
        """
        select signed_state_json, key_id, revision, use_high_water, observed_at, revocation_id
        from guard_workflow_capability_authority_state where capability_id = ?
        """,
        (capability_id,),
    ).fetchone()
    if row is None:
        raise WorkflowCapabilityError("capability_authority_state_missing")
    signed_state = decode_signed_authority_state(str(row["signed_state_json"]))
    verify_authority_state(signed_state, key=key, key_id=key_id)
    state = signed_state.state
    duplicated = (
        capability_id,
        key_id,
        int(row["revision"]),
        int(row["use_high_water"]),
        str(row["observed_at"]),
        str(row["revocation_id"]) if row["revocation_id"] is not None else None,
    )
    authenticated = (
        state.capability_id,
        signed_state.key_id,
        state.revision,
        state.use_high_water,
        state.observed_at,
        state.revocation_id,
    )
    if duplicated != authenticated or state.claim_sha256 != workflow_capability_claim_sha256(signed_claim):
        raise WorkflowCapabilityError("capability_authority_state_binding_invalid")
    receipt_count = _validate_receipt_history(connection, signed_claim, key=key, key_id=key_id)
    if state.use_high_water != receipt_count or used_count != receipt_count:
        raise WorkflowCapabilityError("capability_use_high_water_invalid")
    revocation = _load_revocation(connection, signed_claim, key=key, key_id=key_id)
    if revocation is None:
        if state.revocation_id is not None or revoked_at is not None or revocation_code is not None:
            raise WorkflowCapabilityError("capability_revocation_state_invalid")
    elif (
        state.revocation_id != revocation.revocation_id
        or state.revoked_at != revocation.revoked_at
        or revoked_at != revocation.revoked_at
        or revocation_code != revocation.reason_code
    ):
        raise WorkflowCapabilityError("capability_revocation_state_invalid")
    validate_capability_transition_projection(
        connection,
        signed_claim,
        signed_state,
        receipt_count=receipt_count,
        revocation_id=revocation.revocation_id if revocation is not None else None,
        key=key,
        key_id=key_id,
    )
    return state


def advance_authority_state(
    connection: sqlite3.Connection,
    state: WorkflowCapabilityAuthorityState,
    *,
    key: bytes,
    key_id: str,
    now: str,
    use_high_water: int | None = None,
    revocation_id: str | None = None,
    revoked_at: str | None = None,
) -> SignedAuthorityState:
    if parse_utc_timestamp(now) < parse_utc_timestamp(state.observed_at):
        raise WorkflowCapabilityError("capability_clock_rollback")
    updated = replace(
        state,
        observed_at=now,
        revision=state.revision + 1,
        use_high_water=state.use_high_water if use_high_water is None else use_high_water,
        revocation_id=state.revocation_id if revocation_id is None else revocation_id,
        revoked_at=state.revoked_at if revoked_at is None else revoked_at,
    )
    signed_state = sign_authority_state(updated, key=key, key_id=key_id)
    _write_state(connection, signed_state, insert=False)
    return signed_state


def append_revocation(
    connection: sqlite3.Connection,
    signed_claim: SignedWorkflowCapability,
    *,
    reason_code: str,
    revoked_at: str,
    revocation_id: str,
    key: bytes,
    key_id: str,
) -> WorkflowCapabilityRevocation:
    revocation = WorkflowCapabilityRevocation(
        schema_version=REVOCATION_SCHEMA,
        revocation_id=revocation_id,
        capability_id=signed_claim.claim.capability_id,
        claim_sha256=workflow_capability_claim_sha256(signed_claim),
        reason_code=reason_code,
        revoked_at=revoked_at,
    )
    signed = sign_revocation(revocation, key=key, key_id=key_id)
    connection.execute(
        """
        insert into guard_workflow_capability_revocations
          (revocation_id, capability_id, signed_revocation_json, key_id, revoked_at)
        values (?, ?, ?, ?, ?)
        """,
        (revocation_id, revocation.capability_id, encode_signed_revocation(signed), key_id, revoked_at),
    )
    return revocation


def _write_state(connection: sqlite3.Connection, signed: SignedAuthorityState, *, insert: bool) -> None:
    state = signed.state
    payload = (
        encode_signed_authority_state(signed),
        signed.key_id,
        state.revision,
        state.use_high_water,
        state.observed_at,
        state.revocation_id,
        state.capability_id,
    )
    if insert:
        connection.execute(
            """
            insert into guard_workflow_capability_authority_state
              (signed_state_json, key_id, revision, use_high_water, observed_at, revocation_id, capability_id)
            values (?, ?, ?, ?, ?, ?, ?)
            """,
            payload,
        )
        return
    cursor = connection.execute(
        """
        update guard_workflow_capability_authority_state
        set signed_state_json = ?, key_id = ?, revision = ?, use_high_water = ?,
            observed_at = ?, revocation_id = ?
        where capability_id = ?
        """,
        payload,
    )
    if cursor.rowcount != 1:
        raise WorkflowCapabilityError("capability_authority_state_update_failed")


def _load_revocation(
    connection: sqlite3.Connection,
    signed_claim: SignedWorkflowCapability,
    *,
    key: bytes,
    key_id: str,
) -> WorkflowCapabilityRevocation | None:
    rows = connection.execute(
        """
        select revocation_id, signed_revocation_json, key_id, revoked_at
        from guard_workflow_capability_revocations where capability_id = ?
        """,
        (signed_claim.claim.capability_id,),
    ).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise WorkflowCapabilityError("capability_revocation_history_invalid")
    row = rows[0]
    signed = decode_signed_revocation(str(row["signed_revocation_json"]))
    verify_revocation(signed, key=key, key_id=key_id)
    revocation = signed.revocation
    if (
        str(row["revocation_id"]) != revocation.revocation_id
        or str(row["key_id"]) != signed.key_id
        or str(row["revoked_at"]) != revocation.revoked_at
        or revocation.capability_id != signed_claim.claim.capability_id
        or revocation.claim_sha256 != workflow_capability_claim_sha256(signed_claim)
    ):
        raise WorkflowCapabilityError("capability_revocation_binding_invalid")
    return revocation


def _validate_receipt_history(
    connection: sqlite3.Connection,
    signed_claim: SignedWorkflowCapability,
    *,
    key: bytes,
    key_id: str,
) -> int:
    rows = connection.execute(
        """
        select r.receipt_id, r.task_id, r.invocation_id, r.approval_provenance_id,
               r.signed_receipt_json, r.claimed_at, r.use_number, r.event_id,
               e.event_name, e.payload_json, e.occurred_at
        from guard_workflow_capability_receipts r
        left join guard_events e on e.event_id = r.event_id
        where r.capability_id = ? order by r.use_number
        """,
        (signed_claim.claim.capability_id,),
    ).fetchall()
    for expected_use, row in enumerate(rows, start=1):
        signed = _decode_receipt(str(row["signed_receipt_json"]))
        verify_workflow_capability_receipt(signed, key=key, key_id=key_id)
        receipt = signed.receipt
        if (
            receipt.use_number != expected_use
            or int(row["use_number"]) != expected_use
            or receipt.receipt_id != str(row["receipt_id"])
            or receipt.task_id != str(row["task_id"])
            or receipt.invocation_id != str(row["invocation_id"])
            or receipt.approval_provenance_id != str(row["approval_provenance_id"])
            or receipt.claimed_at != str(row["claimed_at"])
            or receipt.event_id != int(row["event_id"])
            or receipt.capability_id != signed_claim.claim.capability_id
            or receipt.claim_sha256 != workflow_capability_claim_sha256(signed_claim)
            or receipt.binding != signed_claim.claim.binding
        ):
            raise WorkflowCapabilityError("capability_receipt_history_invalid")
        if str(row["event_name"]) != "workflow_capability.claimed" or str(row["occurred_at"]) != receipt.claimed_at:
            raise WorkflowCapabilityError("capability_receipt_event_history_invalid")
        if str(row["payload_json"]) != _canonical(_event_payload(receipt)):
            raise WorkflowCapabilityError("capability_receipt_event_history_invalid")
    return len(rows)


def _decode_receipt(encoded: str) -> SignedWorkflowCapabilityReceipt:
    try:
        payload = json.loads(encoded)
    except json.JSONDecodeError as error:
        raise WorkflowCapabilityError("receipt_payload_invalid") from error
    signed = SignedWorkflowCapabilityReceipt.from_dict(payload)
    if _canonical(signed.to_dict()) != encoded:
        raise WorkflowCapabilityError("receipt_payload_not_canonical")
    return signed


def _event_payload(receipt: WorkflowCapabilityReceipt) -> dict[str, object]:
    return {
        "approval_provenance_ref": _private("approval-provenance", receipt.approval_provenance_id),
        "capability_ref": _private("capability", receipt.capability_id),
        "invocation_ref": _private("invocation", receipt.invocation_id),
        "receipt_ref": _private("receipt", receipt.receipt_id),
        "task_ref": _private("task", receipt.task_id),
        "use_number": receipt.use_number,
    }


def _private(purpose: str, value: str) -> str:
    return hashlib.sha256(canonical_framed_payload(f"audit-{purpose}", value)).hexdigest()


def _canonical(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
