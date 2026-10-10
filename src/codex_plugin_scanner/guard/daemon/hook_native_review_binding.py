"""Bind ordinary local review reuse to its verified native policy domain."""

from __future__ import annotations

import hmac
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

from ..native_decision_receipt import receipt_matches_edge, validate_native_decision_receipt

_SCHEMA = "guard.native-review-policy-binding.v1"


def native_review_policy_binding(
    *, harness: str, native_result: Mapping[str, object], verified_receipt: object
) -> dict[str, object] | None:
    """Capture only a typed native receipt; request payload metadata is not authority.

    Absence on both native surfaces retains the legacy contract. A partially
    present or inconsistent command domain cannot create an unbound approval.
    Receipt persistence is asynchronous and does not participate in this check.
    """

    receipt_bound = isinstance(verified_receipt, Mapping) and "command_extensions" in verified_receipt
    if "command_extensions" not in native_result and not receipt_bound:
        return None
    receipt = validate_native_decision_receipt(verified_receipt)
    if receipt is None or not receipt_matches_edge(
        {
            "harness": harness,
            "event_name": "PreToolUse",
            "payload_kind": receipt["payload_kind"],
            "result": native_result,
        },
        receipt,
    ):
        raise ValueError("native_review_policy_binding_invalid")
    if any(not isinstance(receipt.get(field), str) for field in ("policy_digest", "rule_digest", "runtime_identity")):
        raise ValueError("native_review_policy_binding_invalid")
    command_binding = receipt.get("command_extensions")
    if not isinstance(command_binding, dict):
        raise ValueError("native_review_policy_binding_invalid")
    uncertainty_count = command_binding.get("uncertainty_count")
    if type(uncertainty_count) is not int or uncertainty_count < 0:
        raise ValueError("native_review_policy_binding_invalid")
    return {
        "schema": _SCHEMA,
        "policy_digest": receipt["policy_digest"],
        "rule_digest": receipt["rule_digest"],
        "runtime_identity": receipt["runtime_identity"],
        "command_extensions": dict(command_binding),
    }


def native_review_matching_allow(
    store: object,
    *,
    harness: str,
    artifact_id: str,
    tool_name: str,
    launch_target: str,
    workspace: Path | None,
    identity: str | None,
) -> bool:
    consume = getattr(store, "consume_native_review_approval", None)
    if not callable(consume) or identity is None or not launch_target:
        return False
    try:
        return (
            consume(
                harness=harness,
                artifact_id=artifact_id,
                artifact_name=tool_name,
                artifact_hash=identity,
                launch_target=launch_target,
                workspace=str(workspace) if workspace is not None else None,
                now=datetime.now(tz=timezone.utc).isoformat(),
            )
            is True
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return False


def native_review_claimed_allow(
    store: object,
    *,
    harness: str,
    artifact_id: str,
    workspace: Path | None,
    identity: str | None,
    claimed_saved_allow_hash: str,
    claimed_approval_request_id: str | None,
    claim_saved_approval: bool,
) -> bool:
    """Settle a MAC'd once-approval bound to this exact native request."""

    if identity is None or not hmac.compare_digest(identity, claimed_saved_allow_hash):
        return False
    peek = getattr(store, "peek_local_once_approval", None)
    if not callable(peek):
        return False
    try:
        decision = peek(
            harness=harness,
            artifact_id=artifact_id,
            artifact_hash=identity,
            workspace=str(workspace) if workspace is not None else None,
            publisher=None,
            now=datetime.now(tz=timezone.utc).isoformat(),
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return False
    if not isinstance(decision, Mapping) or decision.get("action") != "allow":
        return False
    if claimed_approval_request_id is not None and decision.get("request_id") != claimed_approval_request_id:
        return False
    if not claim_saved_approval:
        return True
    approval_id = decision.get("approval_id")
    claim = getattr(store, "claim_local_once_approval", None)
    if not isinstance(approval_id, str) or not callable(claim):
        return False
    try:
        return (
            claim(
                approval_id,
                claimed_at=datetime.now(tz=timezone.utc).isoformat(),
                expected_decision=decision,
            )
            is True
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return False
