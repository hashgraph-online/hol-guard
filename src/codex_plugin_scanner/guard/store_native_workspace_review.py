"""SQLite application boundary for native workspace-review decisions."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from contextlib import AbstractContextManager
from typing import Protocol

from .approval_resolution import require_resolvable_approval_request
from .store_approvals import get_approval_request as load_approval_request
from .store_approvals import resolve_request_with_queue_result as persist_queue_resolution


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
    ) -> dict[str, object]:
        if resolution_action not in {"allow", "block"}:
            return {"resolved": False, "error": "native_workspace_review_decision_invalid"}
        if not isinstance(expected_request, Mapping):
            return {"resolved": False, "error": "native_workspace_review_request_invalid"}
        try:
            expected_snapshot = _request_snapshot(expected_request)
        except (TypeError, ValueError):
            return {"resolved": False, "error": "native_workspace_review_request_invalid"}
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
            result["native_replayed"] = native_replayed
            return result


__all__ = ["StoreNativeWorkspaceReviewMixin"]
