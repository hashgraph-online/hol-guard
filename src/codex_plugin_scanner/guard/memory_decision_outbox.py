"""Enqueue memory decision events into the local cloud outbox.

Local Guard approvals and denials previously lived only in local SQLite. This
module is the missing seam that turns a resolved approval request into a
``guard.memory-decision.v1`` event in the existing ``guard_cloud_events``
outbox, so the decision can reach HOL Guard Cloud and become a Suggested Memory
candidate.

Everything here is defensive: if cloud pairing is absent, the store lacks the
outbox, or the request has no command/artifact signal, the enqueue is a no-op.
Local approvals must never fail because the cloud candidate pipeline is not
ready.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from .edge_events import build_memory_decision_event_envelope
from .memory_decision_event import (
    MemoryDecisionSource,
    build_memory_decision_event,
    event_to_cloud_payload,
)

_LOGGER = logging.getLogger(__name__)


def enqueue_memory_decision_event(
    store: Any,
    *,
    request: Mapping[str, object],
    action: str,
    scope: str,
    resolved_at: str,
    source: MemoryDecisionSource = "local_approval_center",
) -> bool:
    """Build and enqueue a memory decision event. Returns True if enqueued.

    ``store`` is a ``GuardStore`` but typed as ``Any`` here to avoid an import
    cycle (GuardStore imports this module's callers). Returns False on any
    non-fatal miss (no cloud pairing, no usable signal, outbox unavailable).
    """
    try:
        workspace_id = _resolve_workspace_id(store)
        device_id, machine_installation_id = _resolve_device_metadata(store)
        owner_user_id = _resolve_owner_user_id(store)
        redaction_enabled = _resolve_redaction_enabled(store)

        event = build_memory_decision_event(
            request=request,
            action=action,
            scope=scope,
            resolved_at=resolved_at,
            owner_user_id=owner_user_id,
            workspace_id=workspace_id,
            device_id=device_id,
            machine_id=machine_installation_id,
            machine_installation_id=machine_installation_id,
            source=source,
            redaction_enabled=redaction_enabled,
        )
        if event is None:
            return False

        envelope = build_memory_decision_event_envelope(
            request_id=event.request_id,
            decision_action=event.decision_action,
            occurred_at=event.occurred_at,
            payload=event_to_cloud_payload(event),
            device_id=device_id,
            workspace_id=workspace_id,
        )
        add_guard_event_v1 = getattr(store, "add_guard_event_v1", None)
        if add_guard_event_v1 is None:
            return False
        add_guard_event_v1(envelope)
        return True
    except Exception as error:
        _LOGGER.debug("memory decision event enqueue skipped: %s", error)
        return False


def _resolve_workspace_id(store: Any) -> str | None:
    getter = getattr(store, "get_cloud_workspace_id", None)
    if callable(getter):
        try:
            value = getter()
        except Exception:
            return None
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _resolve_device_metadata(store: Any) -> tuple[str | None, str | None]:
    getter = getattr(store, "get_device_metadata", None)
    if not callable(getter):
        return None, None
    try:
        metadata = getter()
    except Exception:
        return None, None
    if not isinstance(metadata, Mapping):
        return None, None
    installation_id = metadata.get("installation_id")
    device_id = installation_id if isinstance(installation_id, str) and installation_id.strip() else None
    machine_installation_id = device_id
    return device_id, machine_installation_id


def _resolve_owner_user_id(store: Any) -> str | None:
    credentials = _oauth_credentials(store)
    if not credentials:
        return None
    for key in ("user_id", "owner_user_id", "userId", "ownerUserId"):
        value = credentials.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _resolve_redaction_enabled(store: Any) -> bool:
    config_getter = getattr(store, "get_sync_payload", None)
    if not callable(config_getter):
        return False
    try:
        payload = config_getter("guard_redaction_policy")
    except Exception:
        return False
    if isinstance(payload, Mapping):
        value = payload.get("command_redaction_enabled")
        if isinstance(value, bool):
            return value
    return False


def _oauth_credentials(store: Any) -> Mapping[str, object] | None:
    getter = getattr(store, "get_oauth_local_credentials", None)
    if not callable(getter):
        return None
    try:
        credentials = getter()
    except Exception:
        return None
    if isinstance(credentials, Mapping):
        return credentials
    return None
