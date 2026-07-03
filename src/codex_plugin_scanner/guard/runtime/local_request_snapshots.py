"""Cloud-safe local approval request snapshots for command queue leases."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

from ..config import VALID_RECEIPT_REDACTION_LEVELS, load_guard_config
from ..redaction import redact_text
from ..review_contracts import (
    GuardReviewContractError,
    build_local_review_request_claim,
    guard_review_oauth_metadata,
)
from ..store import GuardStore

LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT = 125
LOCAL_REQUEST_RESOLVED_SNAPSHOT_LIMIT = 25
LOCAL_REQUEST_CURSORLESS_FALLBACK_LIMIT = 500
_LOCAL_REQUEST_SNAPSHOT_CURSOR_SYNC_KEY = "guard_command_local_request_snapshot_cursor"


def local_request_snapshot_items(store: GuardStore) -> list[dict[str, object]]:
    pending_items, _ = _local_request_snapshot_items_for_status(
        store,
        status="pending",
        limit=100,
    )
    resolved_items, _ = _local_request_snapshot_items_for_status(
        store,
        status="resolved",
        limit=100,
    )
    return [*pending_items, *resolved_items]


def local_request_snapshot_payload(store: GuardStore) -> dict[str, object]:
    pending_items, pending_complete = _local_request_snapshot_items_for_status(
        store,
        status="pending",
        limit=LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT,
    )
    resolved_items, resolved_complete = _local_request_snapshot_items_for_status(
        store,
        status="resolved",
        limit=LOCAL_REQUEST_RESOLVED_SNAPSHOT_LIMIT,
    )
    return {
        "requests": [*pending_items, *resolved_items],
        "pendingComplete": pending_complete,
        "resolvedComplete": resolved_complete,
        "pendingLimit": LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT,
        "resolvedLimit": LOCAL_REQUEST_RESOLVED_SNAPSHOT_LIMIT,
        "pendingCount": len(pending_items),
        "resolvedCount": len(resolved_items),
    }


def _local_request_snapshot_items_for_status(
    store: GuardStore,
    *,
    status: str,
    limit: int,
) -> tuple[list[dict[str, object]], bool]:
    items: list[dict[str, object]] = []
    redaction_level = _resolve_cloud_receipt_redaction_level(store)
    try:
        oauth = guard_review_oauth_metadata(store)
    except GuardReviewContractError:
        oauth = None
    cursor_state = _local_request_snapshot_cursor_state(store)
    cursor = cursor_state.get(status)
    rows = store.list_approval_requests(
        status=status,
        limit=limit + 1,
        cursor=cursor if isinstance(cursor, str) and cursor else None,
    )
    if not rows and isinstance(cursor, str) and cursor:
        cursor = None
        rows = store.list_approval_requests(status=status, limit=limit + 1)
    cursor_supported = True
    if len(rows) > limit:
        rows, cursor_supported = _expand_cursorless_small_backlog(
            store,
            status=status,
            rows=rows,
            limit=limit,
        )
        if not cursor_supported:
            cursor = None
    page_limit = min(limit if cursor_supported else LOCAL_REQUEST_CURSORLESS_FALLBACK_LIMIT, len(rows))
    for item in rows[:page_limit]:
        request_id = item.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            continue
        created_at = str(item.get("created_at") or _now())
        last_seen_at = str(item.get("last_seen_at") or created_at)
        resolved_at = item.get("resolved_at")
        claim = None
        if oauth is not None:
            try:
                claim = build_local_review_request_claim(
                    request_row=item,
                    oauth=oauth,
                    store=store,
                )
            except GuardReviewContractError:
                claim = None
        items.append(
            {
                "claim": claim,
                "localRequestId": request_id,
                "requestKind": str(item.get("harness") or "guard-review"),
                "requestPayload": _cloud_safe_local_request_payload(
                    item,
                    redaction_level=redaction_level,
                ),
                "localStatus": str(item.get("status") or status),
                "firstSeenAt": created_at,
                "lastSeenAt": last_seen_at,
                "resolvedAt": str(resolved_at) if isinstance(resolved_at, str) and resolved_at else None,
            }
        )
    if cursor_supported:
        if len(rows) > limit:
            cursor_state[status] = _local_request_snapshot_next_cursor(rows, limit)
        else:
            cursor_state.pop(status, None)
        _save_local_request_snapshot_cursor_state(store, cursor_state)
    complete_limit = limit if cursor_supported else LOCAL_REQUEST_CURSORLESS_FALLBACK_LIMIT
    return items, cursor is None and len(rows) <= complete_limit


def _expand_cursorless_small_backlog(
    store: GuardStore,
    *,
    status: str,
    rows: list[dict[str, object]],
    limit: int,
) -> tuple[list[dict[str, object]], bool]:
    next_cursor = _local_request_snapshot_next_cursor(rows, limit)
    if next_cursor is None or not rows:
        return rows, True
    probe = store.list_approval_requests(status=status, limit=1, cursor=next_cursor)
    first_request_id = rows[0].get("request_id")
    probe_request_id = probe[0].get("request_id") if probe else None
    if not isinstance(first_request_id, str) or probe_request_id != first_request_id:
        return rows, True
    fallback_rows = store.list_approval_requests(
        status=status,
        limit=LOCAL_REQUEST_CURSORLESS_FALLBACK_LIMIT + 1,
    )
    return fallback_rows, False


def _local_request_snapshot_cursor_state(store: GuardStore) -> dict[str, object]:
    value = store.get_sync_payload(_LOCAL_REQUEST_SNAPSHOT_CURSOR_SYNC_KEY)
    return dict(value) if isinstance(value, dict) else {}


def _save_local_request_snapshot_cursor_state(
    store: GuardStore,
    state: dict[str, object],
) -> None:
    cleaned = {
        key: value
        for key, value in state.items()
        if key in {"pending", "resolved"} and isinstance(value, str) and value
    }
    store.set_sync_payload(_LOCAL_REQUEST_SNAPSHOT_CURSOR_SYNC_KEY, cleaned, _now())


def _local_request_snapshot_next_cursor(
    rows: list[dict[str, object]],
    limit: int,
) -> str | None:
    if len(rows) <= limit:
        return None
    last_item = rows[limit - 1]
    payload = {
        "last_seen_at": str(last_item.get("last_seen_at") or last_item.get("created_at") or ""),
        "request_id": str(last_item.get("request_id") or ""),
    }
    if not payload["last_seen_at"] or not payload["request_id"]:
        return None
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
    ).decode("ascii")
    return encoded.rstrip("=")


def _resolve_cloud_receipt_redaction_level(store: GuardStore) -> str:
    payload = store.get_sync_payload("cloud_receipt_redaction_level")
    if isinstance(payload, dict):
        level = payload.get("level")
        if isinstance(level, str) and level in VALID_RECEIPT_REDACTION_LEVELS:
            return level
    try:
        config = load_guard_config(store.guard_home)
        if config.receipt_redaction_level in VALID_RECEIPT_REDACTION_LEVELS:
            return config.receipt_redaction_level
    except Exception:
        pass
    return "full"


def _optional_payload_mapping(value: object) -> dict[str, object] | None:
    return dict(value) if isinstance(value, dict) else None


def _cloud_safe_local_request_payload(
    item: dict[str, object],
    *,
    redaction_level: str,
) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key in (
        "request_id",
        "status",
        "harness",
        "artifact_id",
        "artifact_name",
        "artifact_type",
        "artifact_hash",
        "artifact_label",
        "source_label",
        "trigger_summary",
        "why_now",
        "risk_headline",
        "risk_summary",
        "policy_action",
        "recommended_scope",
        "created_at",
        "last_seen_at",
        "queue_group_id",
        "review_kind",
        "risk_category",
        "capability_category",
        "publisher",
        "package_manager",
        "package_name",
    ):
        value = item.get(key)
        if isinstance(value, (str, int, float, bool)) or value is None:
            payload[key] = value

    envelope = _optional_payload_mapping(item.get("action_envelope_json"))
    safe_envelope = _cloud_safe_action_envelope(envelope, redaction_level=redaction_level)
    if safe_envelope is not None:
        payload["action_envelope_json"] = safe_envelope

    if redaction_level == "full":
        payload["raw_command_text"] = None
        payload["command_text"] = None
        return payload

    command_text = _local_request_command_text(item, envelope)
    if command_text:
        scrubbed = redact_text(command_text).text
        payload["raw_command_text"] = scrubbed
        payload["command_text"] = scrubbed
        payload_envelope = payload.get("action_envelope_json")
        if isinstance(payload_envelope, dict):
            payload_envelope["command"] = scrubbed
    return payload


def _local_request_command_text(
    payload: dict[str, object],
    envelope: dict[str, object] | None,
) -> str | None:
    for key in ("raw_command_text", "rawCommandText", "command_text", "commandText"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    if envelope is None:
        return None
    command = envelope.get("command")
    return command.strip() if isinstance(command, str) and command.strip() else None


def _cloud_safe_action_envelope(
    envelope: dict[str, object] | None,
    *,
    redaction_level: str,
) -> dict[str, object] | None:
    if envelope is None:
        return None
    safe: dict[str, object] = {}
    for key in (
        "schema_version",
        "action_id",
        "harness",
        "event_name",
        "action_type",
        "workspace_hash",
        "tool_name",
        "mcp_server",
        "mcp_tool",
        "target_path_count",
        "network_host_count",
        "package_manager",
    ):
        value = envelope.get(key)
        if isinstance(value, (str, int, float, bool)) or value is None:
            safe[key] = value
    if redaction_level != "full":
        command = envelope.get("command")
        if isinstance(command, str) and command.strip():
            safe["command"] = redact_text(command).text
    if redaction_level == "none":
        for key in ("target_paths", "network_hosts", "package_name", "package_targets"):
            value = envelope.get(key)
            if isinstance(value, list):
                safe[key] = [item for item in value if isinstance(item, str)]
            elif isinstance(value, str):
                safe[key] = value
    return safe or None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
