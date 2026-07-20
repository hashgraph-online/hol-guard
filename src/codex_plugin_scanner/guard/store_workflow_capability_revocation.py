"""Workflow-capability revocation authority operation."""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnusedCallResult=false
# pyright: reportUnusedParameter=false

from __future__ import annotations

import sqlite3
from contextlib import AbstractContextManager
from uuid import uuid4

from .store_workflow_capabilities_schema import ensure_workflow_capability_schema
from .store_workflow_capability_authority import (
    advance_authority_state,
    append_revocation,
    load_and_validate_authority,
)
from .store_workflow_capability_common import (
    WORKFLOW_CAPABILITY_STORE_CLOCK,
    _decode_signed_claim,
    _private_reference,
    _require_store_key,
    _validate_claim_row,
    _validate_reason_code,
    _verify_persisted_claim_signature,
    _workflow_capability_event_payload,
)
from .store_workflow_capability_control import (
    finalize_control_transition,
    load_validate_and_observe_control,
    prepare_control_transition,
)
from .store_workflow_capability_lock import serialized_workflow_capability_authority
from .store_workflow_capability_transitions import append_authority_transition, build_authority_transition
from .workflow_capabilities import validate_workflow_capability_identifier


class StoreWorkflowCapabilityRevocationMixin:
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]:
        raise NotImplementedError

    def hold_workflow_capability_authority_lock(self) -> AbstractContextManager[None]:
        raise NotImplementedError

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]:
        _ = create
        raise NotImplementedError

    def _load_workflow_capability_control(self) -> str | None:
        raise NotImplementedError

    def _store_workflow_capability_control(self, encoded: str) -> bool:
        _ = encoded
        raise NotImplementedError

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
        raise NotImplementedError

    @serialized_workflow_capability_authority
    def revoke_workflow_capability(self, capability_id: str, *, reason_code: str) -> bool:
        now = WORKFLOW_CAPABILITY_STORE_CLOCK.now()
        validate_workflow_capability_identifier("capability_id", capability_id)
        _validate_reason_code(reason_code)
        key, key_id = _require_store_key(self, create=False)
        with self._connect() as connection:
            connection.execute("begin immediate")
            ensure_workflow_capability_schema(connection, applied_at=now)
            control = load_validate_and_observe_control(self, connection, key=key, key_id=key_id, now=now, create=False)
            row = connection.execute(
                """
                select signed_claim_json, key_id, issued_at, not_before, expires_at, max_uses,
                       used_count, revoked_at, revocation_code, approval_provenance_id, nonce
                from guard_workflow_capabilities where capability_id = ?
                """,
                (capability_id,),
            ).fetchone()
            if row is None:
                return False
            signed = _decode_signed_claim(str(row["signed_claim_json"]))
            _validate_claim_row(signed, row, capability_id)
            _verify_persisted_claim_signature(signed, key=key, key_id=key_id)
            state = load_and_validate_authority(
                connection,
                signed,
                key=key,
                key_id=key_id,
                used_count=int(row["used_count"]),
                revoked_at=row["revoked_at"],
                revocation_code=row["revocation_code"],
            )
            if state.revocation_id is not None:
                return False
            revocation_id = f"wcv-{uuid4().hex}"
            append_revocation(
                connection,
                signed,
                reason_code=reason_code,
                revoked_at=now,
                revocation_id=revocation_id,
                key=key,
                key_id=key_id,
            )
            cursor = connection.execute(
                """
                update guard_workflow_capabilities set revoked_at = ?, revocation_code = ?
                where capability_id = ? and revoked_at is null
                """,
                (now, reason_code, capability_id),
            )
            if cursor.rowcount != 1:
                return False
            event_extra: dict[str, object] = {"revocation_ref": _private_reference("revocation-code", reason_code)}
            event_id = self._insert_workflow_capability_event(
                connection,
                event_name="workflow_capability.revoked",
                capability_id=capability_id,
                invocation_id=None,
                occurred_at=now,
                extra=event_extra,
            )
            signed_state = advance_authority_state(
                connection,
                state,
                key=key,
                key_id=key_id,
                now=now,
                revocation_id=revocation_id,
                revoked_at=now,
            )
            transition = build_authority_transition(
                signed,
                signed_state,
                sequence=control.committed_sequence + 1,
                previous_transition_sha256=control.committed_head_sha256,
                transition_kind="revoked",
                event_id=event_id,
                event_name="workflow_capability.revoked",
                event_payload=_workflow_capability_event_payload(capability_id, None, event_extra),
                occurred_at=now,
                use_number=None,
                receipt_id=None,
                revocation_id=revocation_id,
                key=key,
                key_id=key_id,
            )
            pending_control = prepare_control_transition(self, control, transition)
            append_authority_transition(connection, transition)
        finalize_control_transition(self, pending_control)
        return True
