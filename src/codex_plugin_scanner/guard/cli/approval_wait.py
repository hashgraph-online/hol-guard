"""Read-only CLI transport for an approval decision; never consumes the approval."""

from __future__ import annotations

import argparse
import logging
import sqlite3
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
