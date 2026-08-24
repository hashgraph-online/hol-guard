"""Atomic application of one signed exact Cloud Review receipt."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..approval_resolution import approval_resolution_block_reason
from ..approval_scope_support import (
    APPROVAL_SCOPE_CONTRACT_VERSION,
    IneligibleApprovalScopeError,
    request_scope_contract,
    resolve_request_scope_selection,
)
from ..review_contracts import (
    GuardReviewContractError,
    validate_remote_approval_request_binding,
    validated_remote_approval_envelope,
)
from .exact_cloud_review import (
    EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY,
    EXACT_CLOUD_REVIEW_OPERATION,
    ExactCloudReviewError,
    ExactCloudReviewResolution,
    _audit,
    _exact_action,
    _now,
    _oauth_metadata,
    _oauth_state,
    _reject,
    _request_expires_at,
    _request_is_current,
    _text,
    _verified_capability,
)
from .time_support import parse_utc_timestamp

if TYPE_CHECKING:
    from ..store import GuardStore


def apply_exact_cloud_review(
    store: GuardStore,
    *,
    remote_approval: dict[str, object],
    expected_harness: str | None = None,
    now: str | None = None,
) -> ExactCloudReviewResolution:
    """Verify and atomically apply one Cloud decision without policy mutation."""

    current = _now(now)
    try:
        _verified_capability(store, now=current.isoformat())
    except ExactCloudReviewError as error:
        raise _reject(store, error.code, now=current) from error
    raw_capability = store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)
    if not isinstance(raw_capability, dict):
        raise _reject(store, "cloud_review_capability_missing", now=current)
    try:
        _ = _oauth_state(store)
    except ExactCloudReviewError as error:
        raise _reject(store, error.code, now=current) from error
    try:
        # Queue job timestamps are Cloud-controlled and must never admit an expired receipt.
        envelope = validated_remote_approval_envelope(remote_approval, store=store)
        oauth = _oauth_metadata(store)
    except GuardReviewContractError as error:
        raise _reject(store, str(error), now=current) from error
    receipt_expires_at = _text(envelope.get("expiresAt"))
    envelope_expires_at = parse_utc_timestamp(receipt_expires_at)
    if receipt_expires_at is None or envelope_expires_at is None or envelope_expires_at <= current:
        raise _reject(store, "remote_approval_expired", now=current)
    request_id = _text(envelope.get("localRequestId")) or _text(envelope.get("requestId"))
    receipt_id = _text(envelope.get("receiptId"))
    if request_id is None or receipt_id is None:
        raise _reject(store, "remote_exact_fields_missing", now=current)
    if store.has_exact_cloud_review_receipt(receipt_id):
        raise _reject(store, "remote_exact_replayed", now=current)
    request = store.get_approval_request(request_id)
    if not isinstance(request, dict) or request.get("status") != "pending":
        raise _reject(store, "remote_exact_request_not_pending", now=current)
    if not _request_is_current(request, now=current):
        raise _reject(store, "remote_exact_request_expired", now=current)
    request_expires_at = _request_expires_at(request)
    assert request_expires_at is not None
    if expected_harness is not None and request.get("harness") != expected_harness:
        raise _reject(store, "remote_exact_harness_mismatch", now=current)
    action = _exact_action(envelope.get("decision"))
    if action is None:
        raise _reject(store, "remote_exact_decision_invalid", now=current)
    if approval_resolution_block_reason(request) is not None or request.get("policy_action") not in {
        "review",
        "require-reapproval",
    }:
        raise _reject(store, "remote_exact_not_permitted", now=current)
    if envelope.get("scope") != "artifact":
        raise _reject(store, "remote_exact_scope_not_exact", now=current)
    contract = request_scope_contract(request)
    try:
        scope = resolve_request_scope_selection(
            request,
            action=action,
            requested_scope="artifact",
            contract_version=APPROVAL_SCOPE_CONTRACT_VERSION,
            contract_digest=contract.digest,
        ).applied_scope
        validate_remote_approval_request_binding(envelope=envelope, request_row=request, oauth=oauth, store=store)
    except IneligibleApprovalScopeError as error:
        raise _reject(store, "remote_exact_not_permitted", now=current) from error
    except GuardReviewContractError as error:
        raise _reject(store, _binding_error_code(str(error)), now=current) from error
    result = store.resolve_one_request_with_signed_remote_exact_result(
        request_id,
        receipt_id=receipt_id,
        resolution_action=action,
        resolution_scope=scope,
        reason="Guard Cloud signed exact review",
        expected_capability=raw_capability,
        expected_oauth_binding={
            "deviceId": oauth.device_id,
            "grantId": oauth.grant_id,
            "installationId": oauth.installation_id,
            "machineId": oauth.machine_id,
            "runtimeId": oauth.runtime_id,
            "workspaceId": oauth.workspace_id,
        },
        expected_request=request,
        receipt_expires_at=receipt_expires_at,
        request_expires_at=request_expires_at.isoformat(),
    )
    checked_at = parse_utc_timestamp(_text(result.get("checked_at"))) or current
    if result.get("replayed") is True:
        raise _reject(store, "remote_exact_replayed", now=checked_at)
    if result.get("resolved") is not True:
        error = _text(result.get("error")) or "remote_exact_apply_failed"
        raise _reject(store, error, now=checked_at)
    value = result.get("resolved_request")
    resolved = value if isinstance(value, dict) else {}
    resolved_at = parse_utc_timestamp(_text(result.get("resolved_at"))) or checked_at
    _audit(
        store,
        "cloud_review.exact_used",
        {"operation": EXACT_CLOUD_REVIEW_OPERATION, "receipt_id": receipt_id, "request_id": request_id},
        now=resolved_at,
    )
    return ExactCloudReviewResolution(
        action=action,
        receipt_id=receipt_id,
        request_id=request_id,
        resolved_request=resolved,
    )


def _binding_error_code(code: str) -> str:
    if code in {
        "remote_approval_request_id_mismatch",
        "remote_approval_approval_id_mismatch",
        "remote_approval_harness_mismatch",
        "remote_approval_action_hash_mismatch",
        "remote_approval_claim_hash_mismatch",
        "remote_approval_policy_version_mismatch",
        "remote_approval_nonce_mismatch",
    }:
        return "remote_exact_request_stale"
    if code in {
        "remote_approval_workspace_mismatch",
        "remote_approval_installation_mismatch",
        "remote_approval_machine_mismatch",
        "remote_approval_device_mismatch",
    }:
        return "remote_exact_wrong_target"
    if code == "remote_approval_reviewer_not_authorized":
        return "remote_exact_reviewer_not_authorized"
    return code
