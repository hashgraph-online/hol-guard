"""Grok live-hook approval wait and resume metadata."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

from ..approvals import wait_for_approval_requests
from ..store import GuardStore
from .grok_config import (
    GROK_APPROVAL_WAIT_MAX_SECONDS,
    GROK_HOOK_INTERNAL_TIMEOUT_SECONDS,
    GROK_PRETOOL_HOOK_TIMEOUT_SECONDS,
)

_GROK_WAITABLE_ACTIONS = frozenset({"review", "require-reapproval"})


def grok_resume_metadata_from_guard_payload(approval_payload: Mapping[str, object] | None) -> dict[str, object]:
    if approval_payload is None:
        return {}
    request_id = _optional_string(approval_payload.get("primary_approval_request_id"))
    if request_id is None:
        request_ids = _approval_request_ids(approval_payload)
        request_id = request_ids[0] if request_ids else None
    approval_url = _optional_string(approval_payload.get("primary_approval_url"))
    if approval_url is None:
        approval_url = _optional_string(approval_payload.get("approval_url"))
    approval_center_url = _optional_string(approval_payload.get("approval_center_url"))
    metadata: dict[str, object] = {}
    if request_id is not None:
        metadata["approval_request_id"] = request_id
        metadata["resume_poll_path"] = f"/v1/requests/{request_id}"
    if approval_url is not None:
        metadata["approval_url"] = approval_url
    if approval_center_url is not None:
        metadata["approval_center_url"] = approval_center_url
    return metadata


def grok_live_approval_wait_seconds(configured_timeout: int) -> int:
    return min(max(configured_timeout, 0), GROK_APPROVAL_WAIT_MAX_SECONDS)


def wait_for_grok_live_approval(
    *,
    event_name: str,
    policy_action: str,
    response_payload: dict[str, object],
    store: GuardStore,
    timeout_seconds: int,
    json_mode: bool,
    payload: Mapping[str, object] | None = None,
) -> str | None:
    """Wait for the queued Grok approval and return allow, block, or None."""

    canonical_event = event_name.replace("_", "").replace("-", "").lower()
    if json_mode or canonical_event != "pretooluse":
        return None
    if policy_action not in _GROK_WAITABLE_ACTIONS:
        return None
    request_ids = _approval_request_ids(response_payload)
    if not request_ids:
        return None
    wait_timeout_seconds = grok_live_approval_wait_seconds(timeout_seconds)
    if wait_timeout_seconds <= 0:
        return None
    now = _now()
    _mark_grok_operations_waiting(
        store,
        request_ids=request_ids,
        payload=payload if payload is not None else response_payload,
        wait_timeout_seconds=wait_timeout_seconds,
        now=now,
    )
    wait_result = wait_for_approval_requests(
        store=store,
        request_ids=request_ids,
        timeout_seconds=wait_timeout_seconds,
    )
    response_payload["approval_wait"] = wait_result
    if not bool(wait_result.get("resolved")):
        response_payload["review_hint"] = (
            "Approval is still pending in HOL Guard. Approve it, and Grok will resume this exact tool call."
        )
        return None
    wait_items = wait_result.get("items")
    resolved_items = [item for item in (wait_items if isinstance(wait_items, list) else []) if isinstance(item, dict)]
    if any(str(item.get("resolution_action")) == "block" for item in resolved_items):
        response_payload["review_hint"] = "HOL Guard kept this Grok action blocked."
        return "block"
    response_payload["browser_resolution_request_id"] = request_ids[0]
    response_payload["review_hint"] = "Approval received in HOL Guard. Grok is resuming this action."
    return "allow"


def _mark_grok_operations_waiting(
    store: GuardStore,
    *,
    request_ids: list[str],
    payload: Mapping[str, object],
    wait_timeout_seconds: int,
    now: str,
) -> None:
    started_at = datetime.now(timezone.utc)
    deadline_at = started_at + timedelta(seconds=wait_timeout_seconds)
    session_id = _optional_string(payload.get("session_id")) or _optional_string(payload.get("sessionId"))
    wait_metadata: dict[str, object] = {
        "grok_hook_waits_for_approval": True,
        "grok_approval_wait_started_at": started_at.isoformat(),
        "grok_approval_wait_deadline_at": deadline_at.isoformat(),
        "grok_approval_wait_timeout_seconds": wait_timeout_seconds,
    }
    if session_id is not None:
        wait_metadata["session_id"] = session_id
    for request_id in request_ids:
        existing = store.get_guard_operation_for_approval_request(request_id)
        if existing is not None:
            metadata = existing.get("metadata")
            merged = dict(metadata) if isinstance(metadata, Mapping) else {}
            merged.update(wait_metadata)
            store.upsert_guard_operation(
                operation_id=str(existing["operation_id"]),
                session_id=str(existing["session_id"]),
                harness="grok",
                operation_type=str(existing.get("operation_type") or "tool_call"),
                status="waiting_on_approval",
                approval_request_ids=_existing_request_ids(existing, request_id),
                resume_token=(str(existing["resume_token"]) if isinstance(existing.get("resume_token"), str) else None),
                metadata=merged,
                now=now,
            )
            continue
        store.upsert_guard_operation(
            operation_id=f"grok-{request_id}",
            session_id=session_id or f"grok-session-{request_id}",
            harness="grok",
            operation_type="tool_call",
            status="waiting_on_approval",
            approval_request_ids=[request_id],
            resume_token=None,
            metadata=wait_metadata,
            now=now,
        )


def _approval_request_ids(payload: Mapping[str, object]) -> list[str]:
    queued = payload.get("approval_requests")
    ids: list[str] = []
    if isinstance(queued, list):
        for item in queued:
            if isinstance(item, dict):
                request_id = _optional_string(item.get("request_id"))
                if request_id is not None:
                    ids.append(request_id)
    if ids:
        return ids
    primary = _optional_string(payload.get("primary_approval_request_id"))
    return [primary] if primary is not None else []


def _existing_request_ids(operation: Mapping[str, object], request_id: str) -> list[str]:
    approval_request_ids = operation.get("approval_request_ids")
    if isinstance(approval_request_ids, list):
        cleaned = [str(item) for item in approval_request_ids if isinstance(item, str) and item.strip()]
        if cleaned:
            return cleaned
    return [request_id]


def _optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "GROK_APPROVAL_WAIT_MAX_SECONDS",
    "GROK_HOOK_INTERNAL_TIMEOUT_SECONDS",
    "GROK_PRETOOL_HOOK_TIMEOUT_SECONDS",
    "grok_live_approval_wait_seconds",
    "grok_resume_metadata_from_guard_payload",
    "wait_for_grok_live_approval",
]
