"""Store reads for the Cloud-safe local approval request snapshot.

This module only reads the local store: request rows, paging cursors, review
claims and routing identifiers. The native owner projects every row into its
Cloud-safe payload, applies the byte budget and reports completeness; the
cursor state is saved only after it answers.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from contextlib import suppress
from datetime import datetime, timezone

from ..config import VALID_RECEIPT_REDACTION_LEVELS, load_guard_config
from ..review_contracts import (
    GuardReviewContractError,
    GuardReviewOAuthMetadata,
    build_local_review_request_claim,
    guard_review_oauth_metadata,
)
from ..store import GuardStore
from ..synced_policy import validated_synced_policy_bundle
from .cloud_request_native import local_request_snapshot, project_request_row

LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT = 125
LOCAL_REQUEST_RESOLVED_SNAPSHOT_LIMIT = 25
LOCAL_REQUEST_CURSORLESS_FALLBACK_LIMIT = 500
LOCAL_REQUEST_SNAPSHOT_MAX_BYTES = 900_000
_LOCAL_REQUEST_SNAPSHOT_CURSOR_SYNC_KEY = "guard_command_local_request_snapshot_cursor"
_NO_CURSOR_UPDATE = object()


def local_request_snapshot_payload(store: GuardStore) -> dict[str, object]:
    redaction_level = _resolve_cloud_receipt_redaction_level(store)
    try:
        oauth = guard_review_oauth_metadata(store)
    except GuardReviewContractError:
        oauth = None
    routing_inputs = _routing_inputs(store, oauth)
    cursor_state = _local_request_snapshot_cursor_state(store)
    pending, _ = _status_page(
        store, oauth, status="pending", limit=LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT, cursor_state=cursor_state
    )
    resolved, resolved_cursor = _status_page(
        store, oauth, status="resolved", limit=LOCAL_REQUEST_RESOLVED_SNAPSHOT_LIMIT, cursor_state=cursor_state
    )
    payload = local_request_snapshot(
        redaction_level=redaction_level,
        routing_inputs=routing_inputs,
        now=_now(),
        pending=pending,
        resolved=resolved,
    )
    if resolved_cursor is not _NO_CURSOR_UPDATE:
        _apply_cursor_update(store, cursor_state, "resolved", resolved_cursor)
    return payload


def _apply_cursor_update(
    store: GuardStore,
    cursor_state: dict[str, object],
    status: str,
    next_cursor: object,
) -> None:
    if isinstance(next_cursor, str):
        cursor_state[status] = next_cursor
    else:
        cursor_state.pop(status, None)
    _save_local_request_snapshot_cursor_state(store, cursor_state)


def _status_page(
    store: GuardStore,
    oauth: GuardReviewOAuthMetadata | None,
    *,
    status: str,
    limit: int,
    cursor_state: Mapping[str, object],
) -> tuple[dict[str, object], object]:
    use_cursor = status != "pending"
    cursor = cursor_state.get(status) if use_cursor else None
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
        rows, cursor_supported = _expand_cursorless_small_backlog(store, status=status, rows=rows, limit=limit)
        if not cursor_supported:
            cursor = None
    entries: list[dict[str, object]] = []
    for item in rows[: min(limit, len(rows))]:
        request_id = item.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            continue
        entries.append({"row": project_request_row(item), "claim": _claim(store, oauth, item)})
    update: object = _NO_CURSOR_UPDATE
    if cursor_supported and use_cursor:
        update = _local_request_snapshot_next_cursor(rows, limit) if len(rows) > limit else None
    page: dict[str, object] = {"rows": entries, "complete": cursor is None and len(rows) <= limit}
    return page, update


def _claim(
    store: GuardStore, oauth: GuardReviewOAuthMetadata | None, item: dict[str, object]
) -> dict[str, object] | None:
    if oauth is None:
        return None
    try:
        return build_local_review_request_claim(request_row=item, oauth=oauth, store=store)
    except GuardReviewContractError:
        return None


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
    policy_bundle = validated_synced_policy_bundle(store)
    if policy_bundle is not None:
        level = policy_bundle.get("receiptRedactionLevel")
        if isinstance(level, str) and level in VALID_RECEIPT_REDACTION_LEVELS:
            return level
    try:
        config = load_guard_config(store.guard_home)
        if config.receipt_redaction_level in VALID_RECEIPT_REDACTION_LEVELS:
            return config.receipt_redaction_level
    except (OSError, ValueError):
        pass
    return "full"


def _usable(value: object) -> bool:
    """Whether the owner's dual-key rule keeps this raw identifier."""

    if isinstance(value, str):
        return bool(value.strip())
    return value is not None


def _routing_inputs(store: GuardStore, oauth: GuardReviewOAuthMetadata | None) -> dict[str, object]:
    """The raw routing identifiers; the owner normalizes and dual-keys them."""

    if oauth is not None:
        return {
            "workspace_id": getattr(oauth, "workspace_id", None),
            "machine_installation_id": getattr(oauth, "installation_id", None),
            "grant_id": getattr(oauth, "grant_id", None),
            "runtime_id": getattr(oauth, "runtime_id", None),
        }
    credentials = None
    try:
        credentials = store.get_oauth_local_credentials(allow_primary=False)
    except Exception:
        credentials = None
    inputs: dict[str, object] = {}
    if isinstance(credentials, Mapping):
        inputs["workspace_id"] = credentials.get("workspace_id")
        inputs["grant_id"] = credentials.get("grant_id")
        inputs["runtime_id"] = credentials.get("runtime_id")
        inputs["machine_installation_id"] = credentials.get("machine_installation_id") or credentials.get(
            "installation_id"
        )
    if not _usable(inputs.get("machine_installation_id")):
        with suppress(Exception):
            inputs["machine_installation_id"] = store.get_or_create_installation_id()
    return inputs


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
