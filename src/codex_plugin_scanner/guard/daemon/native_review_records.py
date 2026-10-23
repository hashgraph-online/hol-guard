"""Records a queued native review leaves behind: its creation event and the inbox address."""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone

from ..models import format_local_http_origin

_LOGGER = logging.getLogger(__name__)

_DEFAULT_APPROVAL_CENTER_PORT = 4781


def record_silent_native_review_event(store: object, queued: Mapping[str, object]) -> None:
    """Write the local creation event for a silent inbox row. Do not mark a prompt as shown."""

    add_event = getattr(store, "add_event", None)
    if not callable(add_event):
        return
    created_at = queued.get("created_at")
    timestamp = created_at if isinstance(created_at, str) and created_at else datetime.now(tz=timezone.utc).isoformat()
    try:
        add_event(
            "approval.created",
            {
                "request_id": queued.get("request_id"),
                "harness": queued.get("harness"),
                "artifact_id": queued.get("artifact_id"),
                "artifact_name": queued.get("artifact_name"),
                "artifact_type": queued.get("artifact_type"),
                "policy_action": queued.get("policy_action"),
                "recommended_scope": queued.get("recommended_scope"),
                "source_scope": queued.get("source_scope"),
                "workspace": queued.get("workspace"),
                "publisher": queued.get("publisher"),
            },
            timestamp,
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as error:
        _LOGGER.warning("Silent review inbox row saved without approval.created (%s)", type(error).__name__)


def native_review_approval_center_url(store: object) -> str:
    getter = getattr(store, "get_runtime_state", None)
    if callable(getter):
        try:
            state = getter()
        except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
            state = None
        if isinstance(state, dict):
            center = state.get("approval_center_url")
            if isinstance(center, str) and center.strip():
                return center.rstrip("/")
            host = state.get("daemon_host")
            port = state.get("daemon_port")
            if isinstance(host, str) and isinstance(port, int) and port > 0:
                return format_local_http_origin(host, port)
    return format_local_http_origin("127.0.0.1", _DEFAULT_APPROVAL_CENTER_PORT)
