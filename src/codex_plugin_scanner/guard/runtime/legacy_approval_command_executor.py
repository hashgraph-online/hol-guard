"""Compatibility executor for durable legacy Cloud Review queue jobs."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..approval_resolution import require_resolvable_approval_request
from ..approval_scope_support import (
    APPROVAL_SCOPE_CONTRACT_VERSION,
    IneligibleApprovalScopeError,
    request_scope_contract,
    resolve_request_scope_selection,
)
from ..memory_decision_outbox import enqueue_memory_decision_event
from ..models import DECISION_SCOPE_VALUES, DecisionScope
from ..review_contracts import (
    GuardReviewContractError,
    RemoteApprovalDecision,
    guard_review_oauth_metadata,
    normalize_remote_approval_decision,
    validate_remote_approval_request_binding,
    validated_remote_approval_envelope,
)
from ..store import GuardStore
from . import local_request_snapshots
from .command_payload import mapping as _payload_mapping
from .command_payload import optional_text as _optional_string
from .command_payload import result as _result
from .legacy_policy_sync_executor import execute_legacy_policy_sync


@dataclass(frozen=True)
class _ValidatedLegacyApproval:
    request_row: dict[str, object]
    resolution_action: RemoteApprovalDecision
    resolution_scope: DecisionScope
    receipt_id: str
    reason: str


def execute_legacy_approval_operation(
    operation: str,
    *,
    job: dict[str, object],
    payload: dict[str, object],
    store: GuardStore,
    generated_at: str,
    resume_after_approval: Callable[..., dict[str, object]],
) -> dict[str, object]:
    if operation == "guard.localRequests.snapshot":
        return _result(_local_request_snapshot_payload(store), generated_at=generated_at)
    if operation != "guard.approval.resolve":
        return {
            "failureCode": "unsupported_operation",
            "failureMessage": f"Unsupported approval operation: {operation}",
        }
    action = _optional_string(payload.get("action"))
    if action == "policy_sync":
        return execute_legacy_policy_sync(payload, store=store, generated_at=generated_at)
    normalized_action = normalize_remote_approval_decision(action)
    if normalized_action is None:
        raise ValueError("invalid_approval_payload")
    request_id = _target_string(payload, "localRequestId", "local_request_id") or _target_string(
        job, "localRequestId", "local_request_id"
    )
    if request_id is None:
        raise ValueError("invalid_approval_payload")
    request_row = store.get_approval_request(request_id)
    if not isinstance(request_row, dict):
        return _missing_approval_response(request_id, normalized_action, generated_at=generated_at)
    validated = _validate_legacy_approval(
        job=job,
        payload=payload,
        store=store,
        request_id=request_id,
        request_row=request_row,
        normalized_action=normalized_action,
    )
    result = _apply_legacy_approval(
        store=store,
        request_id=request_id,
        validated=validated,
        generated_at=generated_at,
    )
    return _legacy_approval_response(
        store=store,
        request_id=request_id,
        validated=validated,
        result=result,
        generated_at=generated_at,
        resume_after_approval=resume_after_approval,
    )


def _validate_legacy_approval(
    *,
    job: dict[str, object],
    payload: dict[str, object],
    store: GuardStore,
    request_id: str,
    request_row: dict[str, object],
    normalized_action: RemoteApprovalDecision,
) -> _ValidatedLegacyApproval:
    remote_approval = _payload_mapping(payload.get("remoteApproval") or payload.get("remote_approval"))
    if not remote_approval:
        raise ValueError("missing_remote_approval")
    oauth = guard_review_oauth_metadata(store)
    _validate_approval_resolve_target(
        job=job, payload=payload, oauth=oauth, request_row=request_row, local_request_id=request_id
    )
    envelope = validated_remote_approval_envelope(remote_approval, store=store, admitted_at=job.get("createdAt"))
    require_resolvable_approval_request(request_row)
    validate_remote_approval_request_binding(envelope=envelope, request_row=request_row, oauth=oauth, store=store)
    require_resolvable_approval_request(request_row)
    resolution_action = normalize_remote_approval_decision(_optional_string(envelope.get("decision")))
    if resolution_action is None:
        raise ValueError("invalid_remote_approval_decision")
    if normalized_action != resolution_action:
        raise ValueError("remote_approval_decision_mismatch")
    resolution_scope = _optional_string(envelope.get("scope"))
    if _optional_string(request_row.get("policy_action")) not in {"review", "require-reapproval"}:
        raise ValueError("remote_approval_not_permitted")
    if resolution_scope not in DECISION_SCOPE_VALUES:
        raise ValueError("remote_approval_not_permitted")
    contract = request_scope_contract(request_row)
    try:
        scope_selection = resolve_request_scope_selection(
            request_row,
            action=resolution_action,
            requested_scope=resolution_scope,
            contract_version=APPROVAL_SCOPE_CONTRACT_VERSION,
            contract_digest=contract.digest,
        )
    except IneligibleApprovalScopeError as error:
        raise ValueError("remote_approval_not_permitted") from error
    receipt_id = _optional_string(envelope.get("receiptId"))
    if receipt_id is None:
        raise ValueError("invalid_remote_approval_receipt")
    return _ValidatedLegacyApproval(
        request_row=request_row,
        resolution_action=resolution_action,
        resolution_scope=scope_selection.applied_scope,
        receipt_id=receipt_id,
        reason=_optional_string(payload.get("reason")) or "Guard Cloud signed remote approval",
    )


def _apply_legacy_approval(
    *,
    store: GuardStore,
    request_id: str,
    validated: _ValidatedLegacyApproval,
    generated_at: str,
) -> dict[str, object]:
    result = store.resolve_request_with_signed_remote_compat_result(
        request_id,
        receipt_id=validated.receipt_id,
        resolution_action=validated.resolution_action,
        resolution_scope=validated.resolution_scope,
        reason=validated.reason,
        resolved_at=generated_at,
    )
    if result.get("error") == "remote_approval_replayed":
        raise ValueError("remote_approval_replayed")
    return result


def _legacy_approval_response(
    *,
    store: GuardStore,
    request_id: str,
    validated: _ValidatedLegacyApproval,
    result: dict[str, object],
    generated_at: str,
    resume_after_approval: Callable[..., dict[str, object]],
) -> dict[str, object]:
    resolved = result.get("resolved") is True
    if resolved:
        enqueue_memory_decision_event(
            store,
            request={**validated.request_row, "source_receipt_id": validated.receipt_id},
            action=validated.resolution_action,
            scope=validated.resolution_scope,
            resolved_at=generated_at,
            source="cloud_review",
        )
    resume_metadata = (
        resume_after_approval(
            store=store,
            request_row=validated.request_row,
            request_id=request_id,
            action=validated.resolution_action,
            now=generated_at,
        )
        if resolved
        else {}
    )
    confirmed = resolved and _remote_resume_confirmed(resume_metadata, validated.resolution_action)
    daemon_ack_status = "not_resolved"
    if resolved:
        daemon_ack_status = "resolved" if confirmed else "resolved_unconfirmed"
    response_data: dict[str, object] = {
        "action": validated.resolution_action,
        "daemonAckStatus": daemon_ack_status,
        "localRequestId": request_id,
        "remoteDecision": validated.resolution_action,
        "resolution": _remote_resolution_metadata(result),
        "status": "completed" if resolved else "not_resolved",
    }
    response_data.update(resume_metadata)
    return _result(response_data, generated_at=generated_at)


def _missing_approval_response(
    request_id: str, action: RemoteApprovalDecision, *, generated_at: str
) -> dict[str, object]:
    return _result(
        {
            "action": action,
            "localRequestId": request_id,
            "daemonAckStatus": "not_resolved",
            "status": "not_resolved",
        },
        generated_at=generated_at,
    )


def _remote_resume_confirmed(resume_metadata: dict[str, object], action: str) -> bool:
    status = _optional_string(resume_metadata.get("resumeStatus")) or _optional_string(
        resume_metadata.get("continuationStatus")
    )
    if status in {
        "already_resumed",
        "already_sent",
        "blocked",
        "blocked_not_resumed",
        "not_applicable",
        "resumed",
        "sent",
    }:
        return True
    if action != "block" or status != "skipped":
        return False
    detail = resume_metadata.get("codexResume") or resume_metadata.get("harnessResume")
    return isinstance(detail, dict) and detail.get("reason") == "blocked_not_resumed"


def _target_string(mapping: dict[str, object], *keys: str) -> str | None:
    for key in keys:
        value = _optional_string(mapping.get(key))
        if value is not None:
            return value
    return None


def _validate_approval_resolve_target(
    *,
    job: dict[str, object],
    payload: dict[str, object],
    oauth: object,
    request_row: dict[str, object],
    local_request_id: str,
) -> None:
    expected_request_id = _optional_string(request_row.get("request_id"))
    if expected_request_id != local_request_id:
        raise GuardReviewContractError("approval_target_request_mismatch")
    _validate_target_field(
        job,
        payload,
        keys=("targetGrantId", "target_grant_id", "grantId", "grant_id"),
        expected=getattr(oauth, "grant_id", None),
        failure_code="approval_target_grant_mismatch",
        require_expected=True,
    )
    _validate_target_field(
        job,
        payload,
        keys=("targetRuntimeGrantId", "target_runtime_grant_id", "runtimeGrantId", "runtime_grant_id"),
        expected=getattr(oauth, "runtime_id", None),
        failure_code="approval_target_runtime_grant_mismatch",
        require_expected=False,
    )
    _validate_target_field(
        job,
        payload,
        keys=("workspaceId", "workspace_id"),
        expected=getattr(oauth, "workspace_id", None),
        failure_code="approval_target_workspace_mismatch",
        require_expected=True,
    )
    _validate_target_field(
        job,
        payload,
        keys=("localRequestId", "local_request_id"),
        expected=local_request_id,
        failure_code="approval_target_local_request_mismatch",
        require_expected=True,
    )


def _validate_target_field(
    job: dict[str, object],
    payload: dict[str, object],
    *,
    keys: tuple[str, ...],
    expected: object,
    failure_code: str,
    require_expected: bool,
) -> None:
    expected_value = _optional_string(expected)
    if expected_value is None and not require_expected:
        return
    for source in (job, payload):
        for key in keys:
            value = _optional_string(source.get(key))
            if value is not None and value != expected_value:
                raise GuardReviewContractError(failure_code)


def _remote_resolution_metadata(result: dict[str, object]) -> dict[str, object]:
    resolved = result.get("resolved") is True
    metadata: dict[str, object] = {
        "resolved": resolved,
        "status": "resolved" if resolved else "not_resolved",
    }
    error = _optional_string(result.get("error"))
    if error is not None:
        metadata["error"] = error
        metadata["status"] = error
    resolved_request = result.get("resolved_request")
    if isinstance(resolved_request, dict):
        request_id = _optional_string(resolved_request.get("request_id"))
        if request_id is not None:
            metadata["localRequestId"] = request_id
    duplicate_ids = result.get("resolved_duplicate_ids")
    if isinstance(duplicate_ids, list):
        metadata["resolvedDuplicateIds"] = [
            item for item in (_optional_string(value) for value in duplicate_ids) if item is not None
        ]
    return metadata


def _local_request_snapshot_items(store: GuardStore) -> list[dict[str, object]]:
    return local_request_snapshots.local_request_snapshot_items(store)


def _local_request_snapshot_payload(store: GuardStore) -> dict[str, object]:
    return local_request_snapshots.local_request_snapshot_payload(store)


def _local_request_snapshot_items_for_status(
    store: GuardStore,
    *,
    status: str,
    limit: int,
) -> tuple[list[dict[str, object]], bool]:
    return local_request_snapshots._local_request_snapshot_items_for_status(
        store,
        status=status,
        limit=limit,
    )


def _local_request_snapshot_byte_capped_items(
    items: list[dict[str, object]],
    *,
    max_bytes: int,
    existing_items: list[dict[str, object]] | None = None,
) -> tuple[list[dict[str, object]], bool]:
    return local_request_snapshots._local_request_snapshot_byte_capped_items(
        items,
        max_bytes=max_bytes,
        existing_items=existing_items,
    )


__all__ = ["execute_legacy_approval_operation"]
