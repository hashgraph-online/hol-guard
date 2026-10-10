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


def _accept_unconsumed_exact_cloud_allow(
    store: object,
    *,
    harness: str,
    artifact_id: str,
    identity: str,
    claimed_approval_request_id: str | None,
    claim_saved_approval: bool,
) -> bool:
    """Recognize one request-bound Cloud grant without consuming it here.

    Generic once-approval lookup stays blind to these rows. The waiting hook's
    fresh check may see the grant, and the live completion path consumes it.
    """

    if claim_saved_approval or claimed_approval_request_id is None:
        return False
    peek = getattr(store, "peek_exact_cloud_local_once_approval", None)
    if not callable(peek):
        return False
    try:
        decision = peek(
            request_id=claimed_approval_request_id,
            now=datetime.now(tz=timezone.utc).isoformat(),
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return False
    if not isinstance(decision, Mapping) or decision.get("action") != "allow":
        return False
    if decision.get("request_id") != claimed_approval_request_id or decision.get("harness") != harness:
        return False
    artifact_hash = decision.get("artifact_hash")
    if not isinstance(artifact_hash, str) or not hmac.compare_digest(artifact_hash, identity):
        return False
    return decision.get("artifact_id") == artifact_id


def _execution_intent_digest(receipt: object) -> str | None:
    if not isinstance(receipt, Mapping):
        return None
    digest = receipt.get("execution_intent_digest")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        return None
    return digest


def _paused_native_policy_action(claimed_saved_allow_hash: str) -> str | None:
    """Return the policy token frozen into a native-review-v4 pause identity."""

    parts = claimed_saved_allow_hash.split(":")
    if len(parts) not in {6, 7} or parts[0] != "native-review-v4":
        return None
    policy_action = parts[4]
    if policy_action not in {"review", "require-reapproval"}:
        return None
    return policy_action


def _accept_same_action_after_policy_refresh(
    store: object,
    *,
    harness: str,
    artifact_id: str,
    identity: str,
    claimed_saved_allow_hash: str,
    claimed_approval_request_id: str,
    fresh_receipt: Mapping[str, object] | None,
) -> bool:
    """See one exact grant after a policy generation changes its request digest.

    The generation-bound review identity changes when the resident publishes a
    new snapshot. The waiting hook's action does not. Accept the unconsumed
    grant for that request when the fresh receipt names the execution intent
    stored with the original pause. A fresh ``require-reapproval`` is accepted
    only when that paused identity was already ``require-reapproval``. A weaker
    pause, a block, or a different intent does not satisfy it.
    """

    validated = validate_native_decision_receipt(fresh_receipt)
    fresh_intent = _execution_intent_digest(validated)
    if validated is None or fresh_intent is None:
        return False
    request_digest = validated.get("request_digest")
    parts = identity.split(":")
    if (
        not isinstance(request_digest, str)
        or len(parts) not in {6, 7}
        or parts[0] != "native-review-v4"
        or parts[1] != request_digest
        or parts[3] not in {"review", "require-reapproval"}
        or parts[4] not in {"review", "require-reapproval"}
        or validated.get("policy_action") != parts[4]
    ):
        return False
    if (
        validated.get("policy_action") == "require-reapproval"
        and _paused_native_policy_action(claimed_saved_allow_hash) != "require-reapproval"
    ):
        return False
    peek = getattr(store, "peek_exact_cloud_local_once_approval", None)
    load = getattr(store, "get_approval_request", None)
    if not callable(peek) or not callable(load):
        return False
    try:
        decision = peek(
            request_id=claimed_approval_request_id,
            now=datetime.now(tz=timezone.utc).isoformat(),
        )
        request = load(claimed_approval_request_id)
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return False
    if not isinstance(decision, Mapping) or decision.get("action") != "allow":
        return False
    if decision.get("request_id") != claimed_approval_request_id or decision.get("harness") != harness:
        return False
    if decision.get("artifact_id") != artifact_id:
        return False
    artifact_hash = decision.get("artifact_hash")
    if (
        not isinstance(artifact_hash, str)
        or len(artifact_hash) != len(claimed_saved_allow_hash)
        or not hmac.compare_digest(artifact_hash, claimed_saved_allow_hash)
    ):
        return False
    if not isinstance(request, Mapping) or request.get("artifact_hash") != claimed_saved_allow_hash:
        return False
    stored_intent = _execution_intent_digest(request.get("action_envelope_json"))
    return stored_intent is not None and hmac.compare_digest(stored_intent, fresh_intent)


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
    fresh_receipt: Mapping[str, object] | None = None,
) -> bool:
    """Settle a MAC'd once-approval bound to this exact native request."""

    if identity is None:
        return False
    if len(identity) != len(claimed_saved_allow_hash) or not hmac.compare_digest(identity, claimed_saved_allow_hash):
        if claim_saved_approval or claimed_approval_request_id is None:
            return False
        return _accept_same_action_after_policy_refresh(
            store,
            harness=harness,
            artifact_id=artifact_id,
            identity=identity,
            claimed_saved_allow_hash=claimed_saved_allow_hash,
            claimed_approval_request_id=claimed_approval_request_id,
            fresh_receipt=fresh_receipt,
        )
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
    if (
        not isinstance(decision, Mapping)
        or decision.get("action") != "allow"
        or (claimed_approval_request_id is not None and decision.get("request_id") != claimed_approval_request_id)
    ):
        return _accept_unconsumed_exact_cloud_allow(
            store,
            harness=harness,
            artifact_id=artifact_id,
            identity=identity,
            claimed_approval_request_id=claimed_approval_request_id,
            claim_saved_approval=claim_saved_approval,
        )
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
