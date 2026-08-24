"""CLI dispatch for the isolated exact Cloud Review capability."""

from __future__ import annotations

import argparse
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


def _refresh_cloud_review_worker(guard_home: Path) -> dict[str, object]:
    try:
        return {"status": "refreshed", **load_guard_surface_daemon_client(guard_home).refresh_cloud_review_worker()}
    except (GuardDaemonRequestError, RuntimeError):
        return {
            "status": "restart_required",
            "restart_command": "hol-guard daemon repair",
        }


def provision_connect_time_exact_cloud_review(
    *,
    args: argparse.Namespace,
    store: GuardStore,
    guard_home: Path,
    payload: dict[str, object],
    exit_code: int,
) -> dict[str, object]:
    """Honor explicit connect-time consent only after OAuth succeeds."""

    if not bool(getattr(args, "enable_exact_cloud_review", False)):
        return payload
    if exit_code != 0:
        return {**payload, "exact_cloud_review": {"enabled": False, "reason": "connect_not_completed"}}
    try:
        capability = enable_exact_cloud_review(store, issuer="connect-consent")
    except ExactCloudReviewError as error:
        return {**payload, "exact_cloud_review": {"enabled": False, "reason": error.code}}
    return {
        **payload,
        "exact_cloud_review": {
            "capability": capability,
            "enabled": True,
            "worker": _refresh_cloud_review_worker(guard_home),
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
    if command == "status":
        _emit("cloud-review", exact_cloud_review_status(store), bool(getattr(args, "json", False)))
        return 0
    try:
        if command == "enable":
            capability = enable_exact_cloud_review(
                store,
                ttl_seconds=int(getattr(args, "expires_in_days", 30)) * 24 * 60 * 60,
            )
            status = "enabled"
        elif command == "disable":
            capability = disable_exact_cloud_review(store)
            status = "disabled"
        else:
            _emit("cloud-review", {"status": "error", "error": "subcommand_required"}, bool(args.json))
            return 2
    except ExactCloudReviewError as error:
        _emit("cloud-review", {"status": "error", "error": error.code}, bool(getattr(args, "json", False)))
        return 2
    _emit(
        "cloud-review",
        {
            "status": status,
            "capability": capability,
            "worker": _refresh_cloud_review_worker(guard_home),
        },
        bool(getattr(args, "json", False)),
    )
    return 0


__all__ = ["_run_guard_cloud_review_command", "provision_connect_time_exact_cloud_review"]
