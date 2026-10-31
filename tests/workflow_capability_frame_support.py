"""Length-delimited framing and HMAC signing for workflow-capability tests.

The resident owns this framing in production; Guard's Python no longer signs
or frames a capability. These helpers exist so tests can build the envelopes a
caller is not supposed to be able to forge, and assert the resident rejects
them.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict

from codex_plugin_scanner.guard.workflow_capabilities import (
    WORKFLOW_CAPABILITY_ALGORITHM,
    WORKFLOW_CAPABILITY_ENVELOPE_SCHEMA,
    WORKFLOW_CAPABILITY_RECEIPT_ENVELOPE_SCHEMA,
    SignedWorkflowCapability,
    SignedWorkflowCapabilityReceipt,
    WorkflowCapabilityClaim,
    WorkflowCapabilityReceipt,
)

_FRAME_MAGIC = b"hol-guard.workflow-capability\x00"


def canonical_framed_payload(purpose: str, payload: object) -> bytes:
    """Serialize a typed payload with unambiguous length-delimited framing."""
    purpose_bytes = purpose.encode("ascii", errors="strict")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return (
        _FRAME_MAGIC
        + len(purpose_bytes).to_bytes(4, "big")
        + purpose_bytes
        + len(canonical).to_bytes(8, "big")
        + canonical
    )


def sign_workflow_capability(claim: WorkflowCapabilityClaim, *, key: bytes, key_id: str) -> SignedWorkflowCapability:
    authenticated = {
        "algorithm": WORKFLOW_CAPABILITY_ALGORITHM,
        "claim": asdict(claim),
        "envelope_schema": WORKFLOW_CAPABILITY_ENVELOPE_SCHEMA,
        "key_id": key_id,
    }
    signature = hmac.new(key, canonical_framed_payload("claim-envelope", authenticated), hashlib.sha256).hexdigest()
    return SignedWorkflowCapability(
        envelope_schema=WORKFLOW_CAPABILITY_ENVELOPE_SCHEMA,
        algorithm=WORKFLOW_CAPABILITY_ALGORITHM,
        claim=claim,
        key_id=key_id,
        signature=signature,
    )


def sign_workflow_capability_receipt(
    receipt: WorkflowCapabilityReceipt, *, key: bytes, key_id: str
) -> SignedWorkflowCapabilityReceipt:
    authenticated = {
        "algorithm": WORKFLOW_CAPABILITY_ALGORITHM,
        "envelope_schema": WORKFLOW_CAPABILITY_RECEIPT_ENVELOPE_SCHEMA,
        "key_id": key_id,
        "receipt": asdict(receipt),
    }
    signature = hmac.new(key, canonical_framed_payload("receipt-envelope", authenticated), hashlib.sha256).hexdigest()
    return SignedWorkflowCapabilityReceipt(
        envelope_schema=WORKFLOW_CAPABILITY_RECEIPT_ENVELOPE_SCHEMA,
        algorithm=WORKFLOW_CAPABILITY_ALGORITHM,
        receipt=receipt,
        key_id=key_id,
        signature=signature,
    )
