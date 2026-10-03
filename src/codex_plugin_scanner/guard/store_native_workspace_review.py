"""SQLite application boundary for native workspace-review decisions."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from contextlib import AbstractContextManager
from typing import Protocol, cast

from .approval_resolution import require_resolvable_approval_request
from .store_approvals import get_approval_request as load_approval_request
from .store_approvals import resolve_request_with_queue_result as persist_queue_resolution

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


def _same_consumed_decision(previous: object, current: Mapping[str, object]) -> bool:
    if not isinstance(previous, dict):
        return False
    stored = cast(Mapping[str, object], previous)
    return stored.get("decision") == current.get("decision") and all(
        stored.get(field) == current.get(field) for field in _RECEIPT_BINDINGS
    )


class _ConnectionOwner(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...


def _request_snapshot(request: Mapping[str, object]) -> str:
    return json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class StoreNativeWorkspaceReviewMixin:
    """Apply a native decision after the resident has durably claimed it."""

    def resolve_native_workspace_review_request(
        self: _ConnectionOwner,
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
        with self._connect() as connection:
            connection.execute("begin immediate")
            from .runtime.exact_cloud_review import EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY

            if (
                connection.execute(
                    "select 1 from sync_state where state_key = ?",
                    (EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY,),
                ).fetchone()
                is not None
            ):
                return {"resolved": False, "error": "native_workspace_review_cloud_review_disabled"}
            current = load_approval_request(connection, request_id)
            if current is None:
                return {"resolved": False, "error": "native_workspace_review_request_missing"}
            if current.get("status") == "resolved":
                if native_receipt is not None:
                    receipt_row = connection.execute(
                        "select payload_json from sync_state where state_key = ?",
                        (NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + request_id,),
                    ).fetchone()
                    try:
                        previous_receipt = (
                            json.loads(str(receipt_row["payload_json"])) if receipt_row is not None else None
                        )
                    except (TypeError, ValueError):
                        previous_receipt = None
                    if not native_replayed or not _same_consumed_decision(previous_receipt, native_receipt):
                        return {"resolved": False, "error": "native_workspace_review_request_resolved"}
                if (
                    current.get("resolution_action") == resolution_action
                    and current.get("resolution_scope") == "artifact"
                ):
                    return {
                        "resolved": True,
                        "replayed": True,
                        "resolved_request": current,
                        "resolved_duplicate_ids": [],
                    }
                return {"resolved": False, "error": "native_workspace_review_request_resolved"}
            if current.get("status") != "pending":
                return {"resolved": False, "error": "native_workspace_review_request_not_pending"}
            try:
                if _request_snapshot(current) != expected_snapshot:
                    return {"resolved": False, "error": "native_workspace_review_request_stale"}
                require_resolvable_approval_request(current)
            except (TypeError, ValueError):
                return {"resolved": False, "error": "native_workspace_review_request_invalid"}
            result = persist_queue_resolution(
                connection,
                request_id,
                resolution_action=resolution_action,
                resolution_scope="artifact",
                reason="Native workspace review decision",
                resolved_at=resolved_at,
            )
            if result.get("resolved") is True and receipt_json is not None:
                connection.execute(
                    "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)",
                    (NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + request_id, receipt_json, resolved_at),
                )
            result["native_replayed"] = native_replayed
            return result


__all__ = ["NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX", "StoreNativeWorkspaceReviewMixin"]
