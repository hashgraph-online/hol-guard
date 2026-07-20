"""GuardStore boundary for dormant workflow-capability persistence."""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnnecessaryIsInstance=false
# pyright: reportUnusedCallResult=false, reportUnusedFunction=false

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import AbstractContextManager
from datetime import datetime, timezone
from typing import Protocol
from uuid import uuid4

from .store_workflow_capabilities_schema import ensure_workflow_capability_schema
from .store_workflow_capability_authority import (
    advance_authority_state,
    create_authority_state,
    load_and_validate_authority,
)
from .store_workflow_capability_control import (
    finalize_control_transition,
    load_validate_and_observe_control,
    prepare_control_transition,
)
from .store_workflow_capability_lock import serialized_workflow_capability_authority
from .store_workflow_capability_transitions import append_authority_transition, build_authority_transition
from .workflow_capabilities import (
    WORKFLOW_CAPABILITY_RECEIPT_SCHEMA,
    SignedWorkflowCapability,
    SignedWorkflowCapabilityReceipt,
    WorkflowCapabilityBinding,
    WorkflowCapabilityError,
    WorkflowCapabilityReceipt,
    canonical_framed_payload,
    format_utc_timestamp,
    sign_workflow_capability_receipt,
    verify_workflow_capability,
    verify_workflow_capability_signature,
    workflow_capability_claim_sha256,
)


class _WorkflowCapabilityStoreBoundary(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]: ...

    def _load_workflow_capability_control(self) -> str | None: ...

    def _store_workflow_capability_control(self, encoded: str) -> bool: ...


class StoreWorkflowCapabilitiesMixin:
    """Persist and atomically consume exact signed workflow capabilities."""

    def _connect(self) -> AbstractContextManager[sqlite3.Connection]:
        raise NotImplementedError

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]:
        _ = create
        raise NotImplementedError

    def _load_workflow_capability_control(self) -> str | None:
        raise NotImplementedError

    def _store_workflow_capability_control(self, encoded: str) -> bool:
        _ = encoded
        raise NotImplementedError

    @serialized_workflow_capability_authority
    def issue_workflow_capability(
        self,
        signed: SignedWorkflowCapability,
        *,
        approval_provenance_id: str,
    ) -> SignedWorkflowCapability:
        now = _workflow_capability_store_now()
        if type(signed) is not SignedWorkflowCapability:
            raise WorkflowCapabilityError("invalid_signed_capability")
        claim = signed.claim
        _validate_public_identifier("approval_provenance_id", approval_provenance_id)
        if approval_provenance_id != claim.approval_provenance_id:
            raise WorkflowCapabilityError("capability_approval_binding_mismatch")
        key, key_id = _require_store_key(self, create=False)
        verify_workflow_capability(
            signed,
            key=key,
            key_id=key_id,
            now=now,
            expected_binding=claim.binding,
        )
        encoded = _canonical_json(signed.to_dict())
        with self._connect() as connection:
            connection.execute("begin immediate")
            ensure_workflow_capability_schema(connection, applied_at=now)
            control = load_validate_and_observe_control(self, connection, key=key, key_id=key_id, now=now, create=True)
            try:
                connection.execute(
                    """
                    insert into guard_workflow_capabilities (
                      capability_id, approval_provenance_id, nonce, signed_claim_json, key_id, issued_at, not_before,
                      expires_at, max_uses, used_count, revoked_at, revocation_code
                    ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, null, null)
                    """,
                    (
                        claim.capability_id,
                        approval_provenance_id,
                        claim.nonce,
                        encoded,
                        key_id,
                        claim.issued_at,
                        claim.not_before,
                        claim.expires_at,
                        claim.max_uses,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise WorkflowCapabilityError("capability_already_exists") from error
            event_extra: dict[str, object] = {
                "approval_provenance_ref": _private_reference("approval-provenance", approval_provenance_id),
                "max_uses": claim.max_uses,
                "task_ref": _private_reference("task", claim.task_id),
            }
            event_id = self._insert_workflow_capability_event(
                connection,
                event_name="workflow_capability.issued",
                capability_id=claim.capability_id,
                invocation_id=None,
                occurred_at=now,
                extra=event_extra,
            )
            signed_state = create_authority_state(connection, signed, key=key, key_id=key_id, now=now)
            transition = build_authority_transition(
                signed,
                signed_state,
                sequence=control.committed_sequence + 1,
                previous_transition_sha256=control.committed_head_sha256,
                transition_kind="issued",
                event_id=event_id,
                event_name="workflow_capability.issued",
                event_payload=_workflow_capability_event_payload(claim.capability_id, None, event_extra),
                occurred_at=now,
                use_number=None,
                receipt_id=None,
                revocation_id=None,
                key=key,
                key_id=key_id,
            )
            pending_control = prepare_control_transition(self, control, transition)
            append_authority_transition(connection, transition)
        finalize_control_transition(self, pending_control)
        return signed

    @serialized_workflow_capability_authority
    def claim_workflow_capability(
        self,
        capability_id: str,
        *,
        invocation_id: str,
        expected_binding: WorkflowCapabilityBinding,
        expected_subject_id: str,
        expected_task_id: str,
        expected_issuer_id: str,
        expected_approval_provenance_id: str,
    ) -> SignedWorkflowCapabilityReceipt:
        now = _workflow_capability_store_now()
        if type(expected_binding) is not WorkflowCapabilityBinding:
            raise WorkflowCapabilityError("invalid_expected_capability_binding")
        _validate_public_identifier("capability_id", capability_id)
        _validate_public_identifier("invocation_id", invocation_id)
        for name, value in (
            ("expected_subject_id", expected_subject_id),
            ("expected_task_id", expected_task_id),
            ("expected_issuer_id", expected_issuer_id),
            ("expected_approval_provenance_id", expected_approval_provenance_id),
        ):
            _validate_public_identifier(name, value)
        key, key_id = _require_store_key(self, create=False)
        with self._connect() as connection:
            connection.execute("begin immediate")
            ensure_workflow_capability_schema(connection, applied_at=now)
            control = load_validate_and_observe_control(self, connection, key=key, key_id=key_id, now=now, create=False)
            row = connection.execute(
                """
                select signed_claim_json, key_id, issued_at, not_before, expires_at,
                       max_uses, used_count, revoked_at, revocation_code, approval_provenance_id, nonce
                from guard_workflow_capabilities where capability_id = ?
                """,
                (capability_id,),
            ).fetchone()
            if row is None:
                raise WorkflowCapabilityError("capability_not_found")
            signed = _decode_signed_claim(str(row["signed_claim_json"]))
            _validate_claim_row(signed, row, capability_id)
            state = load_and_validate_authority(
                connection,
                signed,
                key=key,
                key_id=key_id,
                used_count=int(row["used_count"]),
                revoked_at=row["revoked_at"],
                revocation_code=row["revocation_code"],
            )
            verify_workflow_capability(
                signed,
                key=key,
                key_id=key_id,
                now=now,
                expected_binding=expected_binding,
            )
            claim = signed.claim
            if (
                claim.subject_id != expected_subject_id
                or claim.task_id != expected_task_id
                or claim.issuer_id != expected_issuer_id
                or claim.approval_provenance_id != expected_approval_provenance_id
            ):
                raise WorkflowCapabilityError("capability_claimant_context_mismatch")
            if state.revocation_id is not None:
                raise WorkflowCapabilityError("capability_revoked")
            used_count = int(row["used_count"])
            if used_count >= signed.claim.max_uses:
                raise WorkflowCapabilityError("capability_exhausted")
            if (
                connection.execute(
                    "select 1 from guard_workflow_capability_receipts where invocation_id = ?",
                    (invocation_id,),
                ).fetchone()
                is not None
            ):
                raise WorkflowCapabilityError("capability_invocation_replayed")

            use_number = used_count + 1
            receipt_id = f"wcr-{uuid4().hex}"
            updated = connection.execute(
                """
                update guard_workflow_capabilities set used_count = ?
                where capability_id = ? and used_count = ? and revoked_at is null
                """,
                (use_number, capability_id, used_count),
            )
            if updated.rowcount != 1:
                raise WorkflowCapabilityError("capability_claim_conflict")
            event_extra = _claim_event_extra(
                approval_provenance_id=signed.claim.approval_provenance_id,
                receipt_id=receipt_id,
                task_id=signed.claim.task_id,
                use_number=use_number,
            )
            event_id = self._insert_workflow_capability_event(
                connection,
                event_name="workflow_capability.claimed",
                capability_id=capability_id,
                invocation_id=invocation_id,
                occurred_at=now,
                extra=event_extra,
            )
            receipt = WorkflowCapabilityReceipt(
                schema_version=WORKFLOW_CAPABILITY_RECEIPT_SCHEMA,
                receipt_id=receipt_id,
                capability_id=capability_id,
                task_id=signed.claim.task_id,
                invocation_id=invocation_id,
                approval_provenance_id=signed.claim.approval_provenance_id,
                claim_sha256=workflow_capability_claim_sha256(signed),
                binding=expected_binding,
                use_number=use_number,
                event_id=event_id,
                claimed_at=now,
            )
            signed_receipt = sign_workflow_capability_receipt(receipt, key=key, key_id=key_id)
            try:
                connection.execute(
                    """
                    insert into guard_workflow_capability_receipts (
                      receipt_id, capability_id, task_id, invocation_id, approval_provenance_id, signed_receipt_json,
                      claimed_at, use_number, event_id
                    ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        receipt.receipt_id,
                        capability_id,
                        receipt.task_id,
                        invocation_id,
                        receipt.approval_provenance_id,
                        _canonical_json(signed_receipt.to_dict()),
                        now,
                        use_number,
                        event_id,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise WorkflowCapabilityError("capability_claim_conflict") from error
            signed_state = advance_authority_state(
                connection,
                state,
                key=key,
                key_id=key_id,
                now=now,
                use_high_water=use_number,
            )
            transition = build_authority_transition(
                signed,
                signed_state,
                sequence=control.committed_sequence + 1,
                previous_transition_sha256=control.committed_head_sha256,
                transition_kind="claimed",
                event_id=event_id,
                event_name="workflow_capability.claimed",
                event_payload=_workflow_capability_event_payload(capability_id, invocation_id, event_extra),
                occurred_at=now,
                use_number=use_number,
                receipt_id=receipt_id,
                revocation_id=None,
                key=key,
                key_id=key_id,
            )
            pending_control = prepare_control_transition(self, control, transition)
            append_authority_transition(connection, transition)
        finalize_control_transition(self, pending_control)
        return signed_receipt

    @staticmethod
    def _insert_workflow_capability_event(
        connection: sqlite3.Connection,
        *,
        event_name: str,
        capability_id: str,
        invocation_id: str | None,
        occurred_at: str,
        extra: dict[str, object],
    ) -> int:
        payload = _workflow_capability_event_payload(capability_id, invocation_id, extra)
        cursor = connection.execute(
            "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
            (event_name, _canonical_json(payload), occurred_at),
        )
        if cursor.lastrowid is None:
            raise WorkflowCapabilityError("capability_event_link_failed")
        return int(cursor.lastrowid)


def _require_store_key(store: _WorkflowCapabilityStoreBoundary, *, create: bool = True) -> tuple[bytes, str]:
    key, key_id = store._policy_integrity_secret_material(create=create)
    if key is None or key_id is None:
        raise WorkflowCapabilityError("capability_key_unavailable")
    return key, key_id


def _workflow_capability_store_now() -> str:
    return format_utc_timestamp(datetime.now(timezone.utc))


def _decode_signed_claim(encoded: str) -> SignedWorkflowCapability:
    try:
        payload = json.loads(encoded)
    except json.JSONDecodeError as error:
        raise WorkflowCapabilityError("capability_payload_invalid") from error
    signed = SignedWorkflowCapability.from_dict(payload)
    if _canonical_json(signed.to_dict()) != encoded:
        raise WorkflowCapabilityError("capability_payload_not_canonical")
    return signed


def _decode_signed_receipt(encoded: str) -> SignedWorkflowCapabilityReceipt:
    try:
        payload = json.loads(encoded)
    except json.JSONDecodeError as error:
        raise WorkflowCapabilityError("receipt_payload_invalid") from error
    signed = SignedWorkflowCapabilityReceipt.from_dict(payload)
    if _canonical_json(signed.to_dict()) != encoded:
        raise WorkflowCapabilityError("receipt_payload_not_canonical")
    return signed


def _verify_persisted_claim_signature(signed: SignedWorkflowCapability, *, key: bytes, key_id: str) -> None:
    verify_workflow_capability_signature(signed, key=key, key_id=key_id)


def _validate_claim_row(signed: SignedWorkflowCapability, row: sqlite3.Row, capability_id: str) -> None:
    claim = signed.claim
    expected = (
        capability_id,
        claim.approval_provenance_id,
        claim.nonce,
        signed.key_id,
        claim.issued_at,
        claim.not_before,
        claim.expires_at,
        claim.max_uses,
    )
    actual = (
        claim.capability_id,
        str(row["approval_provenance_id"]),
        str(row["nonce"]),
        str(row["key_id"]),
        str(row["issued_at"]),
        str(row["not_before"]),
        str(row["expires_at"]),
        int(row["max_uses"]),
    )
    if actual != expected:
        raise WorkflowCapabilityError("capability_row_binding_invalid")


def _private_reference(purpose: str, value: str) -> str:
    return hashlib.sha256(canonical_framed_payload(f"audit-{purpose}", value)).hexdigest()


def _workflow_capability_event_payload(
    capability_id: str, invocation_id: str | None, extra: dict[str, object]
) -> dict[str, object]:
    payload: dict[str, object] = {
        "capability_ref": _private_reference("capability", capability_id),
        **extra,
    }
    if invocation_id is not None:
        payload["invocation_ref"] = _private_reference("invocation", invocation_id)
    return payload


def _claim_event_extra(
    *, approval_provenance_id: str, receipt_id: str, task_id: str, use_number: int
) -> dict[str, object]:
    return {
        "approval_provenance_ref": _private_reference("approval-provenance", approval_provenance_id),
        "receipt_ref": _private_reference("receipt", receipt_id),
        "task_ref": _private_reference("task", task_id),
        "use_number": use_number,
    }


def _claim_event_payload(receipt: WorkflowCapabilityReceipt) -> dict[str, object]:
    return {
        "capability_ref": _private_reference("capability", receipt.capability_id),
        "invocation_ref": _private_reference("invocation", receipt.invocation_id),
        **_claim_event_extra(
            approval_provenance_id=receipt.approval_provenance_id,
            receipt_id=receipt.receipt_id,
            task_id=receipt.task_id,
            use_number=receipt.use_number,
        ),
    }


def _canonical_json(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _validate_public_identifier(name: str, value: str) -> None:
    # Reuse the strict contract parser without exporting its internal validator.
    if type(value) is not str or not value or len(value) > 256 or value.strip() != value or "*" in value:
        raise WorkflowCapabilityError(f"invalid_{name}")
    if any(character.isspace() or ord(character) < 33 or ord(character) > 126 for character in value):
        raise WorkflowCapabilityError(f"invalid_{name}")


def _validate_reason_code(value: str) -> None:
    if type(value) is not str or re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", value) is None:
        raise WorkflowCapabilityError("invalid_reason_code")
