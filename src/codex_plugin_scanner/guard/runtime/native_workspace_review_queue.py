"""Queue adapter for native workspace-review decision delivery."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ..store_native_workspace_review import NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX
from .exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION
from .native_workspace_review import (
    NativeWorkspaceReviewError,
    NativeWorkspaceReviewStore,
    apply_native_workspace_review_decision,
    matching_workspace_review_snapshot,
)

_NATIVE_PAYLOAD_FIELDS = frozenset({"localRequestId", "receiptId", "envelope"})
_MAX_IDENTIFIER_LENGTH = 128


def native_workspace_review_transport_candidate(store: object) -> bool:
    """Routing hint only; delivered jobs still require native verification."""
    guard_home = getattr(store, "guard_home", None)
    if not isinstance(guard_home, Path):
        return False
    authority = guard_home / "native-runtime" / "workspace-review-authority.v1.json"
    try:
        return not authority.is_symlink() and authority.is_file()
    except OSError:
        return False


class NativeWorkspaceReviewQueueError(ValueError):
    """Stable rejection for the native exact-command queue boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class NativeWorkspaceReviewCommand:
    local_request_id: str
    receipt_id: str
    envelope: dict[str, object]


def _text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return value if value and value == value.strip() and len(value) <= _MAX_IDENTIFIER_LENGTH else None


def _mapping(value: object) -> dict[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    raw = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        return None
    return {cast(str, key): nested for key, nested in raw.items()}


def looks_like_native_workspace_review_payload(payload: object) -> bool:
    mapping = _mapping(payload)
    return mapping is not None and bool(set(mapping) & _NATIVE_PAYLOAD_FIELDS)


def native_workspace_review_payload(payload: object) -> NativeWorkspaceReviewCommand | None:
    """Parse the native mode without permitting legacy/mixed fallback."""

    mapping = _mapping(payload)
    if mapping is None or not bool(set(mapping) & _NATIVE_PAYLOAD_FIELDS):
        return None
    if set(mapping) != _NATIVE_PAYLOAD_FIELDS:
        raise NativeWorkspaceReviewQueueError("remote_native_workspace_review_invalid")
    local_request_id = _text(mapping["localRequestId"])
    receipt_id = _text(mapping["receiptId"])
    envelope = _mapping(mapping["envelope"])
    if (
        local_request_id is None
        or any(
            not (character.isascii() and (character.isalnum() or character in "-_.:")) for character in local_request_id
        )
        or receipt_id is None
        or envelope is None
        or not envelope
    ):
        raise NativeWorkspaceReviewQueueError("remote_native_workspace_review_invalid")
    return NativeWorkspaceReviewCommand(local_request_id, receipt_id, envelope)


def is_native_workspace_review_job(job: Mapping[str, object]) -> bool:
    return job.get("operation") == EXACT_CLOUD_REVIEW_OPERATION and looks_like_native_workspace_review_payload(
        job.get("payload")
    )


def require_native_workspace_review_authority(
    store: NativeWorkspaceReviewStore,
    command: NativeWorkspaceReviewCommand,
) -> None:
    """Require resident-verified authority before leasing a pending request.

    A resolved request is deliberately allowed through this preflight only when
    its saved application receipt exists; execution re-verifies the resident
    claim and current authority before returning the idempotent replay.
    """

    get_request = getattr(store, "get_approval_request", None)
    get_payload = getattr(store, "get_sync_payload", None)
    request = get_request(command.local_request_id) if callable(get_request) else None
    if not isinstance(request, dict):
        raise NativeWorkspaceReviewQueueError("native_workspace_review_request_missing")
    status = request.get("status")
    if status == "resolved":
        receipt = (
            get_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + command.local_request_id)
            if callable(get_payload)
            else None
        )
        if not isinstance(receipt, dict):
            raise NativeWorkspaceReviewQueueError("native_workspace_review_receipt_missing")
        return
    if status != "pending":
        raise NativeWorkspaceReviewQueueError("native_workspace_review_request_not_pending")
    guard_home = getattr(store, "guard_home", None)
    if not isinstance(guard_home, Path):
        raise NativeWorkspaceReviewQueueError("native_workspace_review_not_enrolled")
    try:
        matching_workspace_review_snapshot(store, guard_home, command.local_request_id, command.envelope, request)
    except NativeWorkspaceReviewError as error:
        raise NativeWorkspaceReviewQueueError(error.code) from error
    except (OSError, TypeError, ValueError) as error:
        raise NativeWorkspaceReviewQueueError("native_workspace_review_not_enrolled") from error


def execute_native_workspace_review_command(
    store: NativeWorkspaceReviewStore,
    command: NativeWorkspaceReviewCommand,
    *,
    generated_at: str,
) -> dict[str, object]:
    """Apply only the native local decision; never resume an external action."""

    guard_home = getattr(store, "guard_home", None)
    if not isinstance(guard_home, Path):
        raise ValueError("native_workspace_review_not_enrolled")
    try:
        applied = apply_native_workspace_review_decision(
            store,
            guard_home,
            command.local_request_id,
            command.envelope,
            resolved_at=generated_at,
        )
    except NativeWorkspaceReviewError as error:
        raise ValueError(error.code) from error
    resolution_action = applied.get("resolution_action")
    if resolution_action not in {"allow", "block"}:
        raise ValueError("native_workspace_review_response_invalid")
    return {
        "action": resolution_action,
        "applicationReason": None,
        "applicationStatus": "applied",
        "applicationUpdatedAt": generated_at,
        "continuationReason": "native_workspace_review_no_external_replay",
        "continuationStatus": "not_applicable",
        "continuationUpdatedAt": generated_at,
        "localRequestId": command.local_request_id,
        "nativeReplayed": applied.get("native_replayed") is True,
        "receiptId": command.receipt_id,
        "remoteDecision": resolution_action,
        "resolution": {
            "resolvedDuplicateIds": [],
            "resolvedRequest": applied.get("resolved_request"),
        },
        "status": "completed",
    }


__all__ = [
    "NativeWorkspaceReviewCommand",
    "NativeWorkspaceReviewQueueError",
    "execute_native_workspace_review_command",
    "is_native_workspace_review_job",
    "looks_like_native_workspace_review_payload",
    "native_workspace_review_payload",
    "require_native_workspace_review_authority",
]
