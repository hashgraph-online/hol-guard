"""Apply a verified native workspace-review decision to the local approval queue."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

from ..store_native_workspace_review import NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX
from .exact_cloud_review import EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY
from .native_workspace_review_error import (
    NativeWorkspaceReviewError,
    NativeWorkspaceReviewStore,
    _canonical_json_bytes,
)
from .native_workspace_review_staging import (
    _stage_workspace_review_request,
    matching_workspace_review_snapshot,
)
from .native_workspace_review_transport import _native_response


def canonical_workspace_review_decision_bytes(value: object) -> bytes:
    """Return canonical bytes for the signed decision CLI boundary."""

    try:
        return _canonical_json_bytes(value)
    except NativeWorkspaceReviewError as error:
        raise NativeWorkspaceReviewError("native_workspace_review_decision_invalid") from error


def apply_native_workspace_review_decision(
    store: NativeWorkspaceReviewStore,
    guard_home: Path,
    request_id: str,
    decision: object,
    *,
    resolved_at: str | None = None,
) -> dict[str, object]:
    """Verify a native decision and apply it to the local approval queue.

    The resident claim is durable before SQLite application begins. A retry
    can resume the same decision using a fresh signed envelope. Expired proof
    is never extended locally or accepted without native verification.
    """

    if store.get_sync_payload(EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY) is not None:
        raise NativeWorkspaceReviewError("native_workspace_review_cloud_review_disabled")
    if not isinstance(decision, Mapping):
        raise NativeWorkspaceReviewError("native_workspace_review_decision_invalid")
    request = store.get_approval_request(request_id)
    if isinstance(request, dict) and request.get("status") == "resolved":
        return _reverify_resolved_decision(store, guard_home, request_id, request, decision, resolved_at=resolved_at)
    if not isinstance(request, dict):
        raise NativeWorkspaceReviewError("native_workspace_review_request_missing")
    snapshot = matching_workspace_review_snapshot(store, guard_home, request_id, decision, request)
    _, request_snapshot_digest = _stage_workspace_review_request(
        store, guard_home, request_id, request_snapshot=snapshot
    )
    expected_request = request
    response = _native_response(
        guard_home=guard_home,
        request_id=request_id,
        decision=decision,
        request_snapshot_digest=request_snapshot_digest,
    )
    action_value = response.get("decision")
    if not isinstance(action_value, str):
        raise NativeWorkspaceReviewError("native_workspace_review_response_invalid")
    action = action_value
    # The native contract calls a negative decision ``deny``. The local
    # approval queue and its existing waiters use ``block`` as the deny state.
    resolution_action = "block" if action == "deny" else action
    applied = store.resolve_native_workspace_review_request(
        request_id,
        resolution_action=resolution_action,
        expected_request=expected_request,
        resolved_at=resolved_at or datetime.now(timezone.utc).isoformat(),
        native_replayed=bool(response["replayed"]),
        native_receipt=response,
    )
    if applied.get("resolved") is not True:
        raise NativeWorkspaceReviewError(
            str(applied.get("error") or "native_workspace_review_apply_failed"),
            call_stage="verify",
            commit_certainty="committed",
        )
    return {
        "status": "replayed" if response["replayed"] else "verified",
        "request_id": request_id,
        "decision": action,
        "resolution_action": resolution_action,
        "claim_id": response.get("claim_id"),
        "envelope_digest": response.get("envelope_digest"),
        "native_receipt": response,
        "native_replayed": bool(response["replayed"]),
        "application_replayed": bool(applied.get("replayed")),
        "resolved_request": applied.get("resolved_request"),
    }


def _reverify_resolved_decision(
    store: NativeWorkspaceReviewStore,
    guard_home: Path,
    request_id: str,
    request: Mapping[str, object],
    decision: Mapping[str, object],
    *,
    resolved_at: str | None,
) -> dict[str, object]:
    previous = store.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + request_id)
    if not isinstance(previous, dict) or previous.get("request_id") != request_id:
        raise NativeWorkspaceReviewError("native_workspace_review_request_resolved")
    snapshot_digest = previous.get("request_snapshot_digest")
    if not isinstance(snapshot_digest, str) or len(snapshot_digest) != 64:
        raise NativeWorkspaceReviewError("native_workspace_review_receipt_invalid")
    # Do not rewrite a resolved row into a new pending snapshot. Revalidate
    # against the original native snapshot and its durably consumed claim.
    response = _native_response(
        guard_home=guard_home,
        request_id=request_id,
        decision=decision,
        request_snapshot_digest=snapshot_digest,
    )
    if response.get("replayed") is not True:
        raise NativeWorkspaceReviewError(
            "native_workspace_review_decision_replay",
            call_stage="verify",
            commit_certainty="committed",
        )
    resolution_action = "block" if response.get("decision") == "deny" else "allow"
    applied = store.resolve_native_workspace_review_request(
        request_id,
        resolution_action=resolution_action,
        expected_request=request,
        resolved_at=resolved_at or datetime.now(timezone.utc).isoformat(),
        native_replayed=True,
        native_receipt=response,
    )
    if applied.get("resolved") is not True:
        raise NativeWorkspaceReviewError(
            str(applied.get("error") or "native_workspace_review_apply_failed"),
            call_stage="verify",
            commit_certainty="committed",
        )
    return {
        "status": "already_resolved",
        "request_id": request_id,
        "decision": response.get("decision"),
        "resolution_action": resolution_action,
        "claim_id": response.get("claim_id"),
        "envelope_digest": response.get("envelope_digest"),
        "native_receipt": response,
        "native_replayed": True,
        "application_replayed": True,
        "resolved_request": applied.get("resolved_request"),
    }


__all__ = [
    "apply_native_workspace_review_decision",
    "canonical_workspace_review_decision_bytes",
]
