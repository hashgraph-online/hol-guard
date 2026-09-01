"""CLI dispatch for the isolated exact Cloud Review capability."""

from __future__ import annotations

import argparse
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from ..daemon.client import GuardDaemonRequestError, load_guard_surface_daemon_client
from ..runtime.exact_cloud_review import (
    ExactCloudReviewError,
    disable_exact_cloud_review,
    enable_exact_cloud_review,
    exact_cloud_review_status,
)
from ._commands_shared import GuardConfig, GuardStore, HarnessContext
from .commands_support_interaction import _emit


class PendingReviewRequeueError(RuntimeError):
    """Cloud Review activation could not safely requeue existing requests."""


def _refresh_cloud_review_worker(guard_home: Path) -> dict[str, object]:
    try:
        return {"status": "refreshed", **load_guard_surface_daemon_client(guard_home).refresh_command_queue_worker()}
    except (GuardDaemonRequestError, RuntimeError):
        return {
            "status": "restart_required",
            "restart_command": "hol-guard daemon repair",
        }


def _requeue_pending_cloud_review_requests(store: GuardStore) -> int:
    try:
        return store.requeue_pending_review_events(changed_at=datetime.now(timezone.utc).isoformat())
    except sqlite3.Error as error:
        raise PendingReviewRequeueError from error


def apply_connect_time_cloud_review_consent(
    *,
    args: argparse.Namespace,
    store: GuardStore,
    guard_home: Path,
    payload: dict[str, object],
    exit_code: int,
) -> dict[str, object]:
    """Issue the canonical exact-review capability after explicit successful consent."""

    if not bool(getattr(args, "enable_cloud_review", False)):
        return payload
    if exit_code != 0:
        return {**payload, "cloud_review": {"enabled": False, "reason": "connect_not_completed"}}
    previously_enabled = exact_cloud_review_status(store).get("enabled") is True
    try:
        capability = enable_exact_cloud_review(store, issuer="connect-consent")
        pending_requests_requeued = _requeue_pending_cloud_review_requests(store)
    except PendingReviewRequeueError:
        return {
            **payload,
            "cloud_review": {
                "capability_enabled": True,
                "enabled": False,
                "reason": "pending_request_requeue_failed",
                "pending_requests_requeued": 0,
                "pending_request_requeue_status": "retry_required",
                "retained_existing_capability": previously_enabled,
                "activation_status": "enabled_requeue_retry_required",
            },
        }
    except ExactCloudReviewError as error:
        return {**payload, "cloud_review": {"enabled": False, "reason": error.code}}
    worker = _refresh_cloud_review_worker(guard_home)
    ready = worker.get("status") == "refreshed"
    return {
        **payload,
        "cloud_review": {
            "capability": capability,
            "capability_enabled": True,
            "enabled": ready,
            "reason": None if ready else "worker_restart_required",
            "pending_requests_requeued": pending_requests_requeued,
            "pending_request_requeue_status": "requeued",
            "worker": worker,
        },
    }


def _run_guard_cloud_review_command(
    args: argparse.Namespace,
    *,
    guard_home: Path | None = None,
    workspace: Path | None = None,
    context: HarnessContext | None = None,
    store: GuardStore | None = None,
    config: GuardConfig | None = None,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
) -> int:
    del workspace, context, config, input_text, output_stream
    if store is None or guard_home is None:
        raise RuntimeError("Cloud Review requires initialized Guard storage.")
    command = getattr(args, "cloud_review_command", None)
    pending_requests_requeued = 0
    previously_enabled = False
    capability: dict[str, object] | None = None
    if command == "status":
        _emit("cloud-review", exact_cloud_review_status(store), bool(getattr(args, "json", False)))
        return 0
    try:
        if command == "enable":
            previously_enabled = exact_cloud_review_status(store).get("enabled") is True
            capability = enable_exact_cloud_review(
                store,
                ttl_seconds=int(getattr(args, "expires_in_days", 30)) * 24 * 60 * 60,
            )
            pending_requests_requeued = _requeue_pending_cloud_review_requests(store)
            status = "enabled"
        elif command == "disable":
            capability = disable_exact_cloud_review(store)
            status = "disabled"
        else:
            _emit("cloud-review", {"status": "error", "error": "subcommand_required"}, bool(args.json))
            return 2
    except PendingReviewRequeueError:
        _emit(
            "cloud-review",
            {
                "status": "error",
                "error": "pending_request_requeue_failed",
                "capability_enabled": True,
                "pending_requests_requeued": 0,
                "pending_request_requeue_status": "retry_required",
                "retained_existing_capability": previously_enabled,
                "activation_status": "enabled_requeue_retry_required",
                "capability": capability,
            },
            bool(getattr(args, "json", False)),
        )
        return 2
    except ExactCloudReviewError as error:
        _emit("cloud-review", {"status": "error", "error": error.code}, bool(getattr(args, "json", False)))
        return 2
    _emit(
        "cloud-review",
        {
            "status": status,
            "capability": capability,
            **(
                {
                    "pending_requests_requeued": pending_requests_requeued,
                    "pending_request_requeue_status": "requeued",
                }
                if command == "enable"
                else {}
            ),
            "worker": _refresh_cloud_review_worker(guard_home),
        },
        bool(getattr(args, "json", False)),
    )
    return 0


__all__ = ["_run_guard_cloud_review_command", "apply_connect_time_cloud_review_consent"]
