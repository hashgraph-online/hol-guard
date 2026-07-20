"""Persisted workflow-capability receipt lookup and revalidation."""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from contextlib import AbstractContextManager

from .store_workflow_capabilities_schema import ensure_workflow_capability_schema
from .store_workflow_capability_common import (
    WORKFLOW_CAPABILITY_STORE_CLOCK,
    _canonical_json,
    _claim_event_payload,
    _decode_signed_receipt,
    _require_store_key,
)
from .store_workflow_capability_control import load_validate_and_observe_control
from .store_workflow_capability_lock import serialized_workflow_capability_authority
from .store_workflow_capability_lookup import require_validated_workflow_capability
from .workflow_capabilities import (
    SignedWorkflowCapabilityReceipt,
    WorkflowCapabilityError,
    validate_workflow_capability_identifier,
    verify_workflow_capability_receipt,
    workflow_capability_claim_sha256,
)


class StoreWorkflowCapabilityReceiptLookupMixin:
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

    @serialized_workflow_capability_authority
    def lookup_workflow_capability_receipt(
        self,
        *,
        receipt_id: str | None = None,
        invocation_id: str | None = None,
    ) -> SignedWorkflowCapabilityReceipt | None:
        if (receipt_id is None) == (invocation_id is None):
            raise WorkflowCapabilityError("receipt_lookup_requires_exact_selector")
        selector_name = "receipt_id" if receipt_id is not None else "invocation_id"
        selector_value = receipt_id if receipt_id is not None else invocation_id
        if selector_value is None:
            raise WorkflowCapabilityError("receipt_lookup_requires_exact_selector")
        validate_workflow_capability_identifier(selector_name, selector_value)
        key, key_id = _require_store_key(self, create=False)
        with self._connect() as connection:
            connection.execute("begin")
            now = WORKFLOW_CAPABILITY_STORE_CLOCK.now()
            ensure_workflow_capability_schema(connection, applied_at=now)
            load_validate_and_observe_control(self, connection, key=key, key_id=key_id, now=now, create=False)
            row = connection.execute(
                f"""
                select r.receipt_id, r.capability_id, r.task_id, r.invocation_id,
                       r.approval_provenance_id as receipt_approval_provenance_id,
                       r.signed_receipt_json, r.claimed_at, r.use_number, r.event_id,
                       e.event_name, e.payload_json as event_payload_json, e.occurred_at
                from guard_workflow_capability_receipts r
                left join guard_events e on e.event_id = r.event_id
                where r.{selector_name} = ?
                """,
                (selector_value,),
            ).fetchone()
            if row is None:
                return None
            signed_claim = require_validated_workflow_capability(
                connection,
                str(row["capability_id"]),
                key=key,
                key_id=key_id,
            )
            signed_receipt = _decode_signed_receipt(str(row["signed_receipt_json"]))
            verify_workflow_capability_receipt(signed_receipt, key=key, key_id=key_id)
            receipt = signed_receipt.receipt
            duplicated = (
                str(row["receipt_id"]),
                str(row["capability_id"]),
                str(row["task_id"]),
                str(row["invocation_id"]),
                str(row["receipt_approval_provenance_id"]),
                str(row["claimed_at"]),
                int(row["use_number"]),
                int(row["event_id"]),
            )
            signed_values = (
                receipt.receipt_id,
                receipt.capability_id,
                receipt.task_id,
                receipt.invocation_id,
                receipt.approval_provenance_id,
                receipt.claimed_at,
                receipt.use_number,
                receipt.event_id,
            )
            if duplicated != signed_values:
                raise WorkflowCapabilityError("receipt_row_binding_invalid")
            claim = signed_claim.claim
            if (
                receipt.capability_id != claim.capability_id
                or receipt.task_id != claim.task_id
                or receipt.approval_provenance_id != claim.approval_provenance_id
                or receipt.binding != claim.binding
                or receipt.claim_sha256 != workflow_capability_claim_sha256(signed_claim)
            ):
                raise WorkflowCapabilityError("receipt_claim_binding_invalid")
            if (
                str(row["event_name"]) != "workflow_capability.claimed"
                or str(row["occurred_at"]) != receipt.claimed_at
                or str(row["event_payload_json"]) != _canonical_json(_claim_event_payload(receipt))
            ):
                raise WorkflowCapabilityError("receipt_event_binding_invalid")
            return signed_receipt
