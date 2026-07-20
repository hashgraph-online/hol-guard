"""Signed append-only workflow-capability authority transition ledger."""

# pyright: reportAny=false, reportUnusedCallResult=false

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import cast

from .workflow_capabilities import (
    SignedWorkflowCapability,
    WorkflowCapabilityError,
    canonical_framed_payload,
    workflow_capability_claim_sha256,
)
from .workflow_capability_authority_state import SignedAuthorityState, encode_signed_authority_state
from .workflow_capability_transitions import (
    AUTHORITY_TRANSITION_ALGORITHM,
    AUTHORITY_TRANSITION_SCHEMA,
    ZERO_TRANSITION_SHA256,
    SignedAuthorityTransition,
    WorkflowCapabilityAuthorityTransition,
    authority_transition_sha256,
    decode_signed_authority_transition,
    encode_signed_authority_transition,
    sign_authority_transition,
    verify_authority_transition,
)


def build_authority_transition(
    signed_claim: SignedWorkflowCapability,
    signed_state: SignedAuthorityState,
    *,
    sequence: int,
    previous_transition_sha256: str,
    transition_kind: str,
    event_id: int,
    event_name: str,
    event_payload: dict[str, object],
    occurred_at: str,
    use_number: int | None,
    receipt_id: str | None,
    revocation_id: str | None,
    key: bytes,
    key_id: str,
) -> SignedAuthorityTransition:
    transition = WorkflowCapabilityAuthorityTransition(
        schema_version=AUTHORITY_TRANSITION_SCHEMA,
        algorithm=AUTHORITY_TRANSITION_ALGORITHM,
        sequence=sequence,
        capability_id=signed_claim.claim.capability_id,
        claim_sha256=workflow_capability_claim_sha256(signed_claim),
        revision=signed_state.state.revision,
        transition_kind=transition_kind,
        previous_transition_sha256=previous_transition_sha256,
        signed_state_sha256=_state_sha256(signed_state),
        event_id=event_id,
        event_name=event_name,
        event_payload_sha256=_event_payload_sha256(event_payload),
        occurred_at=occurred_at,
        use_number=use_number,
        receipt_id=receipt_id,
        revocation_id=revocation_id,
    )
    return sign_authority_transition(transition, key=key, key_id=key_id)


def append_authority_transition(connection: sqlite3.Connection, signed: SignedAuthorityTransition) -> None:
    transition = signed.transition
    connection.execute(
        """
        insert into guard_workflow_capability_authority_transitions
          (sequence, capability_id, revision, transition_kind, previous_transition_sha256,
           signed_transition_json, key_id, event_id)
        values (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            transition.sequence,
            transition.capability_id,
            transition.revision,
            transition.transition_kind,
            transition.previous_transition_sha256,
            encode_signed_authority_transition(signed),
            signed.key_id,
            transition.event_id,
        ),
    )


def validate_global_authority_ledger(connection: sqlite3.Connection, *, key: bytes, key_id: str) -> tuple[int, str]:
    rows = connection.execute(
        """
        select sequence, capability_id, revision, transition_kind, previous_transition_sha256,
               signed_transition_json, key_id, event_id
        from guard_workflow_capability_authority_transitions order by sequence
        """
    ).fetchall()
    previous = ZERO_TRANSITION_SHA256
    transition_event_ids: set[int] = set()
    for expected_sequence, row in enumerate(rows, start=1):
        signed = decode_signed_authority_transition(str(row["signed_transition_json"]))
        verify_authority_transition(signed, key=key, key_id=key_id)
        transition = signed.transition
        if transition.event_id is None:
            raise WorkflowCapabilityError("capability_authority_transition_chain_invalid")
        duplicated = (
            int(row["sequence"]),
            str(row["capability_id"]),
            int(row["revision"]),
            str(row["transition_kind"]),
            str(row["previous_transition_sha256"]),
            str(row["key_id"]),
            int(row["event_id"]),
        )
        authenticated = (
            transition.sequence,
            transition.capability_id,
            transition.revision,
            transition.transition_kind,
            transition.previous_transition_sha256,
            signed.key_id,
            transition.event_id,
        )
        if (
            duplicated != authenticated
            or transition.sequence != expected_sequence
            or transition.previous_transition_sha256 != previous
        ):
            raise WorkflowCapabilityError("capability_authority_transition_chain_invalid")
        _validate_transition_event(connection, transition)
        transition_event_ids.add(int(transition.event_id))
        previous = authority_transition_sha256(signed)
    event_rows = connection.execute(
        """
        select event_id from guard_events
        where event_name in ('workflow_capability.issued', 'workflow_capability.claimed',
                             'workflow_capability.revoked')
        """
    ).fetchall()
    if {int(row["event_id"]) for row in event_rows} != transition_event_ids or len(event_rows) != len(rows):
        raise WorkflowCapabilityError("capability_authority_event_cardinality_invalid")
    return len(rows), previous


def validate_capability_transition_projection(
    connection: sqlite3.Connection,
    signed_claim: SignedWorkflowCapability,
    signed_state: SignedAuthorityState,
    *,
    receipt_count: int,
    revocation_id: str | None,
    key: bytes,
    key_id: str,
) -> None:
    rows = connection.execute(
        """
        select signed_transition_json from guard_workflow_capability_authority_transitions
        where capability_id = ? order by revision
        """,
        (signed_claim.claim.capability_id,),
    ).fetchall()
    if not rows:
        raise WorkflowCapabilityError("capability_authority_transition_missing")
    transitions: list[WorkflowCapabilityAuthorityTransition] = []
    for expected_revision, row in enumerate(rows):
        signed = decode_signed_authority_transition(str(row["signed_transition_json"]))
        verify_authority_transition(signed, key=key, key_id=key_id)
        transition = signed.transition
        if (
            transition.revision != expected_revision
            or transition.capability_id != signed_claim.claim.capability_id
            or transition.claim_sha256 != workflow_capability_claim_sha256(signed_claim)
        ):
            raise WorkflowCapabilityError("capability_authority_transition_projection_invalid")
        transitions.append(transition)
    if transitions[0].transition_kind != "issued" or any(
        transition.transition_kind == "issued" for transition in transitions[1:]
    ):
        raise WorkflowCapabilityError("capability_authority_transition_projection_invalid")
    claims = [transition for transition in transitions if transition.transition_kind == "claimed"]
    if [transition.use_number for transition in claims] != list(range(1, receipt_count + 1)):
        raise WorkflowCapabilityError("capability_authority_transition_projection_invalid")
    receipt_rows = connection.execute(
        """select receipt_id, use_number, event_id from guard_workflow_capability_receipts
        where capability_id = ? order by use_number""",
        (signed_claim.claim.capability_id,),
    ).fetchall()
    if [(transition.receipt_id, transition.use_number, transition.event_id) for transition in claims] != [
        (str(row["receipt_id"]), int(row["use_number"]), int(row["event_id"])) for row in receipt_rows
    ]:
        raise WorkflowCapabilityError("capability_authority_transition_projection_invalid")
    revokes = [transition for transition in transitions if transition.transition_kind == "revoked"]
    if len(revokes) != (1 if revocation_id is not None else 0):
        raise WorkflowCapabilityError("capability_authority_transition_projection_invalid")
    if revokes and (revokes[0].revocation_id != revocation_id or revokes[0] is not transitions[-1]):
        raise WorkflowCapabilityError("capability_authority_transition_projection_invalid")
    if transitions[-1].revision != signed_state.state.revision or transitions[-1].signed_state_sha256 != _state_sha256(
        signed_state
    ):
        raise WorkflowCapabilityError("capability_authority_transition_projection_invalid")


def _validate_transition_event(
    connection: sqlite3.Connection, transition: WorkflowCapabilityAuthorityTransition
) -> None:
    row = connection.execute(
        "select event_name, payload_json, occurred_at from guard_events where event_id = ?",
        (transition.event_id,),
    ).fetchone()
    if row is None or (
        str(row["event_name"]) != transition.event_name
        or str(row["occurred_at"]) != transition.occurred_at
        or _event_payload_sha256(_decode_event_payload(str(row["payload_json"]))) != transition.event_payload_sha256
    ):
        raise WorkflowCapabilityError("capability_authority_transition_event_invalid")


def _decode_event_payload(encoded: str) -> dict[str, object]:
    try:
        payload = json.loads(encoded)
    except json.JSONDecodeError as error:
        raise WorkflowCapabilityError("capability_authority_transition_event_invalid") from error
    if (
        type(payload) is not dict
        or json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) != encoded
    ):
        raise WorkflowCapabilityError("capability_authority_transition_event_invalid")
    return cast(dict[str, object], payload)


def _state_sha256(signed: SignedAuthorityState) -> str:
    return hashlib.sha256(
        canonical_framed_payload("authority-state-digest", encode_signed_authority_state(signed))
    ).hexdigest()


def _event_payload_sha256(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical_framed_payload("authority-event", encoded)).hexdigest()
