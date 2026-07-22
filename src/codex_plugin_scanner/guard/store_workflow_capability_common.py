"""Dependency-only helpers shared by workflow-capability store mixins."""

# pyright: reportAny=false, reportPrivateUsage=false

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Protocol

from .workflow_capabilities import (
    SignedWorkflowCapability,
    SignedWorkflowCapabilityReceipt,
    WorkflowCapabilityError,
    WorkflowCapabilityReceipt,
    canonical_framed_payload,
    format_utc_timestamp,
    verify_workflow_capability_signature,
)


class _WorkflowCapabilityStoreBoundary(Protocol):
    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]: ...


def _require_store_key(store: _WorkflowCapabilityStoreBoundary, *, create: bool = True) -> tuple[bytes, str]:
    key, key_id = store._policy_integrity_secret_material(create=create)
    if key is None or key_id is None:
        raise WorkflowCapabilityError("capability_key_unavailable")
    return key, key_id


class WorkflowCapabilityStoreClock:
    def now(self) -> str:
        return format_utc_timestamp(datetime.now(timezone.utc))


WORKFLOW_CAPABILITY_STORE_CLOCK = WorkflowCapabilityStoreClock()


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


def _validate_reason_code(value: str) -> None:
    if type(value) is not str or re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", value) is None:
        raise WorkflowCapabilityError("invalid_reason_code")
