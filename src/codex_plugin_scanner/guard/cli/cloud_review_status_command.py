"""Read Cloud Review status before ordinary CLI storage initialization."""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

from ..config import DEFAULT_GUARD_DIRNAME
from ..daemon.cloud_review_status_reader import read_cloud_review_worker_observation
from ..runtime.cloud_review_status import cloud_review_status
from ..runtime.exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION
from .commands_support_interaction import _emit


def resolve_cloud_review_status_home(args: argparse.Namespace) -> Path:
    """Select the current storage path without invoking legacy-home migration."""
    override = getattr(args, "guard_home", None) or getattr(args, "home", None)
    return Path(override).expanduser().resolve() if override else Path.home() / DEFAULT_GUARD_DIRNAME


def run_cloud_review_status_command(args: argparse.Namespace, *, guard_home: Path, allow_system_keyring: bool) -> int:
    source = getattr(args, "source", "default")
    payload: dict[str, object]
    try:
        if bool(getattr(args, "support_export", False)):
            from ..policy_support_export import build_policy_support_export

            payload = build_policy_support_export(guard_home, source=source, allow_system_keyring=allow_system_keyring)
        else:
            payload = cloud_review_status(
                guard_home,
                source=source,
                allow_system_keyring=allow_system_keyring,
                worker_observation=read_cloud_review_worker_observation(guard_home),
            )
    except (OSError, RuntimeError, ValueError, sqlite3.DatabaseError):
        payload = {
            "status": "unavailable",
            "operation": EXACT_CLOUD_REVIEW_OPERATION,
            "enabled": False,
            "consent_enabled": False,
            "connected": False,
            "delivery_ready": None,
            "delivery_readiness_reason": "local_status_unavailable",
            "reason": "local_status_unavailable",
            "source": source,
            "workspace_id": None,
            "expires_at": None,
            "last_synced_at": None,
            "message": "Cloud Review status is unavailable. Open Guard setup or repair to check local storage.",
        }
    _emit("cloud-review", payload, bool(getattr(args, "json", False)))
    return 0
