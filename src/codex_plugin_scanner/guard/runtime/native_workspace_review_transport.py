"""Submit and reconcile a native workspace-review decision over the resident transport."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from ..native_resident_client import (
    native_resident_client_failure_code,
    native_resident_client_failure_context,
    native_resident_client_request,
)
from ..native_runtime import _isolated_environment, native_runtime_status
from .native_transport_retry import native_transport_security_rejection
from .native_workspace_review_error import NativeWorkspaceReviewError, _canonical_json_bytes

_NATIVE_CONSUMPTION_QUERY_FEATURE = "native-workspace-review-consumption-query-v1"
_NATIVE_RESIDENT_FEATURE = "resident-protocol-v2"
_NATIVE_REVIEW_FEATURE = "native-workspace-review-decision-v1"
_MAX_DECISION_BYTES = 16 * 1024


def _native_response(
    *,
    guard_home: Path,
    request_id: str,
    decision: Mapping[str, object],
    request_snapshot_digest: str,
) -> dict[str, object]:
    status = native_runtime_status()
    identity = status.identity
    capabilities = status.capabilities
    features = capabilities.features if capabilities is not None else ()
    if not status.available or not status.compatible or identity is None or capabilities is None:
        raise NativeWorkspaceReviewError("native_workspace_review_unavailable")
    if _NATIVE_RESIDENT_FEATURE not in features or _NATIVE_REVIEW_FEATURE not in features:
        raise NativeWorkspaceReviewError("native_workspace_review_unsupported")
    payload = _canonical_json_bytes(
        {
            "operation": "workspace_review_decision",
            "request": {"request_id": request_id, "decision": decision},
        }
    )
    if len(payload) > _MAX_DECISION_BYTES:
        raise NativeWorkspaceReviewError("native_workspace_review_decision_invalid")
    try:
        return _submit_native_decision(
            guard_home=guard_home,
            executable=identity.path,
            payload=payload,
            request_id=request_id,
            request_snapshot_digest=request_snapshot_digest,
        )
    except NativeWorkspaceReviewError as first_error:
        if (
            first_error.commit_certainty not in {"unknown", "committed"}
            or native_transport_security_rejection(first_error.code)
            or _NATIVE_CONSUMPTION_QUERY_FEATURE not in features
        ):
            raise
        # Observe the protected journal; never resend a consuming operation.
        query = _canonical_json_bytes(
            {
                "operation": "workspace_review_decision_consumption",
                "request": {"request_id": request_id, "decision": decision},
            }
        )
        try:
            return _submit_native_decision(
                guard_home=guard_home,
                executable=identity.path,
                payload=query,
                request_id=request_id,
                request_snapshot_digest=request_snapshot_digest,
                require_consumed=True,
            )
        except NativeWorkspaceReviewError as query_error:
            if native_transport_security_rejection(query_error.code) or (
                query_error.code.startswith("native_workspace_review_")
                and query_error.code
                not in {
                    "native_workspace_review_consumption_unconfirmed",
                    "native_workspace_review_response_invalid",
                    "native_workspace_review_transport_failed",
                }
            ):
                raise
            raise first_error from None


def _submit_native_decision(
    *,
    guard_home: Path,
    executable: Path,
    payload: bytes,
    request_id: str,
    request_snapshot_digest: str,
    require_consumed: bool = False,
) -> dict[str, object]:
    encoded = native_resident_client_request(
        executable=executable,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=payload,
        timeout_seconds=10.0,
    )
    if encoded is None:
        stage, certainty = native_resident_client_failure_context() or ("read", "unknown")
        raise NativeWorkspaceReviewError(
            native_resident_client_failure_code() or "native_workspace_review_transport_failed",
            call_stage=stage,
            commit_certainty=certainty,
        )
    try:
        decoded: object = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise NativeWorkspaceReviewError(
            "native_workspace_review_response_invalid", call_stage="read", commit_certainty="unknown"
        ) from error
    if not isinstance(decoded, dict):
        raise NativeWorkspaceReviewError(
            "native_workspace_review_response_invalid", call_stage="read", commit_certainty="unknown"
        )
    response = cast(dict[str, object], decoded)
    error = response.get("error")
    if isinstance(error, str) and error:
        # The authenticated resident rejects overload before dispatching a job.
        certainty = "pre_commit" if error == "native_overloaded" and response.get("retryable") is True else "unknown"
        raise NativeWorkspaceReviewError(error, call_stage="read", commit_certainty=certainty)
    if require_consumed and (response.get("status") != "replayed" or response.get("replayed") is not True):
        raise NativeWorkspaceReviewError(
            "native_workspace_review_consumption_unconfirmed",
            call_stage="read",
            commit_certainty="unknown",
        )
    if response.get("request_id") != request_id:
        raise NativeWorkspaceReviewError(
            "native_workspace_review_response_invalid", call_stage="read", commit_certainty="unknown"
        )
    if response.get("status") not in {"verified", "replayed"}:
        raise NativeWorkspaceReviewError(
            "native_workspace_review_response_invalid", call_stage="read", commit_certainty="unknown"
        )
    if response.get("replayed") is not (response.get("status") == "replayed"):
        raise NativeWorkspaceReviewError(
            "native_workspace_review_response_invalid", call_stage="read", commit_certainty="unknown"
        )
    if response.get("decision") not in {"allow", "deny"}:
        raise NativeWorkspaceReviewError(
            "native_workspace_review_response_invalid", call_stage="read", commit_certainty="unknown"
        )
    if response.get("request_snapshot_digest") != request_snapshot_digest:
        raise NativeWorkspaceReviewError(
            "native_workspace_review_response_invalid", call_stage="read", commit_certainty="unknown"
        )
    return response
