"""Read-only CLI transport for an approval decision; never consumes the approval."""

from __future__ import annotations

import argparse
import logging
import sqlite3
from datetime import datetime, timezone
from typing import cast

from ..approvals import wait_for_approval_requests
from ..native_approval_scope import ApprovalScopeUnavailableError
from ..native_signal_projection import NativeSignalProjectionUnavailableError
from ..store import GuardStore


def run_approval_wait_command(args: argparse.Namespace, *, store: GuardStore) -> tuple[dict[str, object], int]:
    request_id = args.request_id
    try:
        result = wait_for_approval_requests(
            store=store,
            request_ids=[request_id],
            timeout_seconds=args.timeout,
            poll_interval=0.25,
            stop_on_missing=True,
        )
    except (
        ApprovalScopeUnavailableError,
        NativeSignalProjectionUnavailableError,
        sqlite3.Error,
        OSError,
        TimeoutError,
    ):
        logging.getLogger(__name__).debug("Approval decision wait could not read the store", exc_info=True)
        return {"error": "approval_store_unavailable", "request_id": request_id, "status": "unknown"}, 3
    if result.get("missing_request_ids"):
        return {"error": "not_found", "request_id": request_id}, 1
    if not result["resolved"]:
        if _cloud_review_window_closed(store, request_id):
            return {
                "error": "approval_expired",
                "request_id": request_id,
                "status": "expired",
                "title": "Nobody answered in time",
                "body": (
                    "Nobody answered this request in Cloud Review within 10 minutes, so it expired. "
                    "The action stays blocked; do not retry it. Tell the person it needs their approval "
                    "and continue with permitted work."
                ),
            }, 2
        return {"error": "approval_wait_timeout", "request_id": request_id, "status": "pending"}, 2
    item = cast(list[dict[str, object]], result["items"])[0]
    action = str(item.get("resolution_action", ""))
    return {
        "request_id": request_id,
        "status": "resolved",
        "resolution_action": action,
        "title": "Approval decision received",
        "body": (
            "Retry the identical action through Guard; the retry revalidates its approval binding."
            if action == "allow"
            else "Keep this action blocked. Continue with permitted work."
        ),
    }, 0 if action == "allow" else 1


def _cloud_review_window_closed(store: GuardStore, request_id: str) -> bool:
    """True when a Cloud Review answer can no longer arrive for this pending request.

    Only a machine paired with Cloud Review sends the request there with a
    deadline. A local-only request never expires, so it keeps the plain timeout.
    """

    from ..review_contracts import cloud_review_request_expiry

    binding_reader = getattr(store, "get_review_event_oauth_binding", None)
    try:
        if binding_reader is None or binding_reader() is None:
            return False
        item = store.get_approval_request(request_id)
        if not isinstance(item, dict) or item.get("status") != "pending":
            return False
        return datetime.now(timezone.utc) >= cloud_review_request_expiry(item)
    except (
        ApprovalScopeUnavailableError,
        NativeSignalProjectionUnavailableError,
        ValueError,
        sqlite3.Error,
        OSError,
        RuntimeError,
    ):
        logging.getLogger(__name__).debug("Cloud Review deadline could not be read", exc_info=True)
        return False
