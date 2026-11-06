"""SQLite application boundary for native workspace-review decisions."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Protocol

NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX = "native_workspace_review.receipt:"
_RECEIPT_BINDINGS = (
    "claim_id",
    "workspace_binding",
    "device_binding",
    "installation_binding",
    "scope_binding",
    "request_binding",
    "action_binding",
    "intent_binding",
    "revision_binding",
    "policy_binding",
    "retry_scope_binding",
    "request_snapshot_digest",
)


def _receipt_payload(receipt: Mapping[str, object], request_id: str, action: str) -> str:
    expected_decision = "deny" if action == "block" else "allow"
    if (
        receipt.get("request_id") != request_id
        or receipt.get("decision") != expected_decision
        or receipt.get("status") not in {"verified", "replayed"}
        or receipt.get("replayed") is not (receipt.get("status") == "replayed")
    ):
        raise ValueError("native_workspace_review_receipt_invalid")
    for field in (*_RECEIPT_BINDINGS, "envelope_digest", "authority_record_digest"):
        value = receipt.get(field)
        if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("native_workspace_review_receipt_invalid")
    return json.dumps(dict(receipt), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


class _NativeStore(Protocol):
    def _native_approval_read(self, method: str, args: dict[str, object]) -> Any: ...


def _request_snapshot(request: Mapping[str, object]) -> str:
    return json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class StoreNativeWorkspaceReviewMixin:
    """Apply a native decision after the resident has durably claimed it."""

    def resolve_native_workspace_review_request(
        self: _NativeStore,
        request_id: str,
        *,
        resolution_action: str,
        expected_request: Mapping[str, object],
        resolved_at: str,
        native_replayed: bool,
        native_receipt: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        if resolution_action not in {"allow", "block"}:
            return {"resolved": False, "error": "native_workspace_review_decision_invalid"}
        if not isinstance(expected_request, Mapping):
            return {"resolved": False, "error": "native_workspace_review_request_invalid"}
        try:
            expected_snapshot = _request_snapshot(expected_request)
        except (TypeError, ValueError):
            return {"resolved": False, "error": "native_workspace_review_request_invalid"}
        try:
            if native_receipt is not None and native_receipt.get("replayed") is not native_replayed:
                raise ValueError("native_workspace_review_receipt_invalid")
            receipt_json = (
                _receipt_payload(native_receipt, request_id, resolution_action) if native_receipt is not None else None
            )
        except (TypeError, ValueError):
            return {"resolved": False, "error": "native_workspace_review_receipt_invalid"}
        return self._native_approval_read(
            "resolve_native_workspace_review_request",
            {
                "request_id": request_id,
                "resolution_action": resolution_action,
                "expected_snapshot": expected_snapshot,
                "resolved_at": resolved_at,
                "native_replayed": native_replayed,
                "native_receipt_json": receipt_json,
            },
        )


__all__ = ["NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX", "StoreNativeWorkspaceReviewMixin"]
