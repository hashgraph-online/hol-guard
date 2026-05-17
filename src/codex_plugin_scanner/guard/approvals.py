"""Approval queue orchestration for local Guard reviews."""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from .adapters import get_adapter
from .adapters.base import HarnessContext
from .config import load_guard_config
from .desktop_notifications import DesktopApprovalNotification, notify_pending_approval_once
from .incident import build_incident_context
from .models import GuardApprovalRequest, HarnessDetection, PolicyDecision
from .risk import artifact_risk_signals, artifact_risk_summary
from .store import GuardStore

GUARD_COMMAND = "hol-guard"
GUARD_DASHBOARD_URL = "https://hol.org/guard"
GUARD_INBOX_URL = f"{GUARD_DASHBOARD_URL}/inbox"
GUARD_FLEET_URL = f"{GUARD_DASHBOARD_URL}/fleet"
GUARD_CONNECT_URL = f"{GUARD_DASHBOARD_URL}/connect"
_WORKSPACE_SCOPED_RUNTIME_ARTIFACT_TYPES = frozenset(
    {
        "file_read_request",
        "prompt_request",
        "tool_action_request",
    }
)


class ApprovalRequestNotFoundError(ValueError):
    """Raised when an approval request ID does not exist."""


class ApprovalRequestAlreadyResolvedError(ValueError):
    """Raised when an approval request was already resolved."""


def queue_blocked_approvals(
    *,
    detection: HarnessDetection,
    evaluation: dict[str, object],
    store: GuardStore,
    approval_center_url: str,
    now: str | None = None,
) -> list[dict[str, object]]:
    timestamp = now or _now()
    artifacts_by_id = {artifact.artifact_id: artifact for artifact in detection.artifacts}
    queued: list[dict[str, object]] = []
    for item in evaluation.get("artifacts", []):
        if not isinstance(item, dict):
            continue
        policy_action = item.get("policy_action")
        if policy_action not in {"block", "sandbox-required", "require-reapproval"}:
            continue
        artifact_id = str(item.get("artifact_id") or "")
        if not artifact_id:
            continue
        artifact = artifacts_by_id.get(artifact_id)
        request_id = uuid.uuid4().hex
        risk_summary = _item_risk_summary(item, artifact)
        launch_target = _launch_target(artifact, item)
        incident = build_incident_context(
            harness=detection.harness,
            artifact=artifact,
            artifact_id=artifact_id,
            artifact_name=_artifact_name(item, artifact_id),
            artifact_type=artifact.artifact_type if artifact is not None else _artifact_type(item),
            source_scope=_source_scope(item, artifact),
            config_path=_config_path(item, artifact),
            changed_fields=_string_list(item.get("changed_fields")),
            policy_action=str(policy_action),
            launch_target=launch_target,
            risk_summary=risk_summary,
        )
        request = GuardApprovalRequest(
            request_id=request_id,
            harness=detection.harness,
            artifact_id=artifact_id,
            artifact_name=_artifact_name(item, artifact_id),
            artifact_type=artifact.artifact_type if artifact is not None else "artifact",
            artifact_hash=str(item.get("artifact_hash") or "unknown"),
            policy_action=str(policy_action),
            recommended_scope="publisher" if artifact is not None and artifact.publisher else "artifact",
            changed_fields=tuple(_string_list(item.get("changed_fields"))),
            source_scope=_source_scope(item, artifact),
            config_path=_config_path(item, artifact),
            launch_target=launch_target,
            transport=artifact.transport if artifact is not None else None,
            review_command=f"{GUARD_COMMAND} approvals approve {request_id}",
            approval_url=f"{approval_center_url.rstrip('/')}/approvals/{request_id}",
            workspace=_workspace_scope_target(item, artifact),
            publisher=artifact.publisher if artifact is not None else None,
            risk_summary=risk_summary,
            risk_signals=_item_risk_signals(item, artifact),
            artifact_label=incident["artifact_label"],
            source_label=incident["source_label"],
            trigger_summary=incident["trigger_summary"],
            why_now=incident["why_now"],
            launch_summary=incident["launch_summary"],
            risk_headline=incident["risk_headline"],
            action_envelope_json=_item_action_envelope_json(item),
            decision_v2_json=_item_decision_v2_json(item),
            scanner_evidence=_item_scanner_evidence(item),
        )
        persisted_request_id = store.add_approval_request(request, timestamp)
        if persisted_request_id != request.request_id:
            request = replace(
                request,
                request_id=persisted_request_id,
                review_command=f"{GUARD_COMMAND} approvals approve {persisted_request_id}",
                approval_url=f"{approval_center_url.rstrip('/')}/approvals/{persisted_request_id}",
            )
        _notify_pending_approval(store=store, request=request)
        queued.append(request.to_dict())
    return queued


def apply_approval_resolution(
    *,
    store: GuardStore,
    request_id: str,
    action: str,
    scope: str,
    workspace: str | None,
    reason: str | None,
    now: str | None = None,
    return_queue_result: bool = False,
    resolve_scope_matches: bool = True,
) -> dict[str, object]:
    request = store.get_approval_request(request_id)
    if request is None:
        raise ApprovalRequestNotFoundError(f"Unknown approval request: {request_id}")
    if request["status"] != "pending":
        raise ApprovalRequestAlreadyResolvedError(f"Approval request already resolved: {request_id}")
    if scope == "workspace" and not workspace:
        raise ValueError(f"Approval request {request_id} requires --workspace for workspace scope.")
    if scope == "publisher" and _string_or_none(request.get("publisher")) is None:
        raise ValueError(f"Approval request {request_id} has no publisher scope to approve.")
    workspace_artifact_id, workspace_artifact_hash = _workspace_policy_artifact_keys(request, scope)
    request_artifact_id = _string_or_none(request.get("artifact_id"))
    request_artifact_hash = _string_or_none(request.get("artifact_hash"))
    request_publisher = _string_or_none(request.get("publisher"))
    harness_artifact_id = request_artifact_id if scope == "harness" else None
    scoped_artifact_id = request_artifact_id if scope == "artifact" else workspace_artifact_id or harness_artifact_id
    decision = PolicyDecision(
        harness="*" if scope == "global" else str(request["harness"]),
        scope=scope,
        action="allow" if action == "allow" else "block",
        artifact_id=scoped_artifact_id,
        artifact_hash=request_artifact_hash if scope == "artifact" else workspace_artifact_hash,
        workspace=workspace if scope == "workspace" else None,
        publisher=request_publisher if scope == "publisher" else None,
        reason=reason,
    )
    store.upsert_policy(decision, now or _now())
    resolved_at = now or _now()
    resolution_harness = None if scope == "global" else str(request["harness"])
    if return_queue_result:
        result = store.resolve_request_with_queue_result(
            request_id,
            resolution_action=action,
            resolution_scope=scope,
            reason=reason,
            resolved_at=resolved_at,
        )
        if result.get("resolved") is not True:
            error = result.get("error")
            if error == "already_resolved":
                raise ApprovalRequestAlreadyResolvedError(f"Approval request already resolved: {request_id}")
            if error == "not_found":
                raise ApprovalRequestNotFoundError(f"Unknown approval request: {request_id}")
        if resolve_scope_matches:
            resolved_scope_ids = store.resolve_matching_approval_requests(
                harness=resolution_harness,
                scope=scope,
                artifact_id=scoped_artifact_id,
                workspace=workspace if scope == "workspace" else None,
                publisher=(
                    str(request["publisher"])
                    if scope == "publisher" and isinstance(request.get("publisher"), str)
                    else None
                ),
                resolution_action=action,
                resolution_scope=scope,
                reason=reason,
                resolved_at=resolved_at,
            )
            if resolved_scope_ids:
                _refresh_queue_result(store, result, resolved_scope_ids)
        _record_resolution_event(store, request_id, action, scope, resolved_at)
        return result
    resolved_ids: list[str] = []
    if resolve_scope_matches:
        resolved_ids = store.resolve_matching_approval_requests(
            harness=resolution_harness,
            scope=scope,
            artifact_id=scoped_artifact_id,
            workspace=workspace if scope == "workspace" else None,
            publisher=(
                str(request["publisher"])
                if scope == "publisher" and isinstance(request.get("publisher"), str)
                else None
            ),
            resolution_action=action,
            resolution_scope=scope,
            reason=reason,
            resolved_at=resolved_at,
        )
    if request_id not in resolved_ids:
        store.resolve_approval_request(
            request_id,
            resolution_action=action,
            resolution_scope=scope,
            reason=reason,
            resolved_at=resolved_at,
        )
    updated = store.get_approval_request(request_id)
    if updated is None:
        raise ValueError(f"Approval request disappeared: {request_id}")
    _record_resolution_event(store, request_id, action, scope, resolved_at)
    return updated


def _workspace_policy_artifact_keys(request: Mapping[str, object], scope: str) -> tuple[str | None, str | None]:
    if scope != "workspace" or request.get("artifact_type") not in _WORKSPACE_SCOPED_RUNTIME_ARTIFACT_TYPES:
        return None, None
    artifact_id = request.get("artifact_id")
    artifact_hash = request.get("artifact_hash")
    if not isinstance(artifact_id, str) or not artifact_id:
        return None, None
    if not isinstance(artifact_hash, str) or not artifact_hash:
        return artifact_id, None
    return artifact_id, artifact_hash


def _notify_pending_approval(*, store: GuardStore, request: GuardApprovalRequest) -> None:
    try:
        config = load_guard_config(store.guard_home)
    except Exception:
        config = None
    if config is not None and not config.desktop_notifications:
        return
    if store.approval_desktop_notified_at(request.request_id) is not None:
        return
    notify_pending_approval_once(
        DesktopApprovalNotification(
            request_id=request.request_id,
            title="HOL Guard needs approval",
            message=_approval_notification_message(request),
            approval_url=request.approval_url,
        ),
        on_success=lambda: store.mark_approval_desktop_notified(
            request.request_id,
            _now(),
        ),
    )


def _approval_notification_message(request: GuardApprovalRequest) -> str:
    subject = request.risk_headline or request.trigger_summary or request.artifact_name
    harness = request.harness.replace("-", " ").title()
    message = f"{harness} wants approval: {subject}"
    if len(message) <= 180:
        return message
    return f"{message[:177].rstrip()}..."


def _string_or_none(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def _record_resolution_event(store: GuardStore, request_id: str, action: str, scope: str, resolved_at: str) -> None:
    store.add_event(
        "approval.resolved",
        {"request_id": request_id, "action": action, "scope": scope},
        resolved_at,
    )


def _refresh_queue_result(
    store: GuardStore,
    result: dict[str, object],
    resolved_scope_ids: list[str],
) -> None:
    page = store.list_pending_approval_summaries(limit=10)
    next_request = store.get_next_pending_request()
    remaining_count = int(page["total_pending_count"])
    result["remaining_pending_count"] = remaining_count
    result["next_selectable_request_id"] = next_request["request_id"] if next_request is not None else None
    result["remaining_pending_summaries"] = page["items"]
    result["resolved_scope_ids"] = resolved_scope_ids
    if remaining_count == 0:
        result["resolution_summary"] = "Decision saved. No blocked actions remain."
    elif remaining_count == 1:
        result["resolution_summary"] = "Decision saved. 1 blocked action remains."
    else:
        result["resolution_summary"] = f"Decision saved. {remaining_count} blocked actions remain."


def approval_center_hint(
    *,
    context: HarnessContext,
    harness: str,
    approval_center_url: str,
    queued: list[dict[str, object]],
    managed_install: dict[str, object] | None = None,
) -> str:
    del context
    flow = approval_prompt_flow(harness, managed_install=managed_install)
    count = len(queued)
    risk_summary = _queue_risk_summary(queued)
    approval_url = first_approval_url(queued)
    review_url = approval_url or approval_center_url
    return (
        f"Guard queued {count} approval request{'s' if count != 1 else ''} for {harness}. "
        f"{flow['summary']} "
        f"Review them in the Guard approval center at {review_url}. "
        f"{risk_summary} "
        f"{flow['fallback_hint']}"
    )


def first_approval_url(queued: Sequence[object]) -> str | None:
    for item in queued:
        if not isinstance(item, Mapping):
            continue
        approval_url = item.get("approval_url")
        if isinstance(approval_url, str) and approval_url.strip():
            return approval_url.strip()
    return None


def build_runtime_snapshot(
    *,
    store: GuardStore,
    approval_center_url: str | None,
    now: str | None = None,
    request_limit: int = 200,
    receipt_limit: int = 25,
    active_request_id: str | None = None,
) -> dict[str, object]:
    pending_requests = store.list_approval_requests(limit=request_limit)
    queue_page = store.list_pending_approval_summaries(limit=1)
    queue_items = queue_page["items"] if isinstance(queue_page["items"], list) else []
    active_request = store.get_approval_request(active_request_id) if active_request_id else None
    active_is_pending = active_request is not None and active_request.get("status") == "pending"
    first_request_id = str(queue_items[0]["request_id"]) if queue_items else None
    next_request_id = active_request_id if active_is_pending else first_request_id
    latest_receipts = store.list_receipts(limit=receipt_limit)
    cloud_context = _build_runtime_cloud_context(store)
    snapshot_now = now or _now()
    latest_connect_state = _build_latest_connect_state(store, snapshot_now)
    headline_state = _resolve_runtime_headline_state(
        pending_count=store.count_approval_requests(),
        runtime_state=store.get_runtime_state(),
        cloud_state=str(cloud_context["cloud_state"]),
    )
    return {
        "generated_at": snapshot_now,
        "approval_center_url": approval_center_url,
        "runtime_state": store.get_runtime_state(),
        "device": _build_runtime_device_context(store),
        "latest_connect_state": latest_connect_state,
        "proof_status": _build_runtime_proof_status(latest_connect_state),
        "pending_count": store.count_approval_requests(),
        "queue_summary": {
            "active_request_id": active_request_id if active_is_pending else None,
            "next_request_id": next_request_id,
            "remaining_pending_count": int(queue_page["total_pending_count"]),
            "next_selectable_request_id": next_request_id,
        },
        "next_request_id": next_request_id,
        "receipt_count": store.count_receipts(),
        "headline_state": headline_state,
        "headline_label": _runtime_headline_label(headline_state),
        "headline_detail": _runtime_headline_detail(headline_state),
        "thread_count": threading.active_count(),
        "items": pending_requests,
        "latest_receipts": latest_receipts,
        "managed_installs": store.list_managed_installs(),
        **cloud_context,
    }


def approval_prompt_flow(
    harness: str,
    *,
    managed_install: dict[str, object] | None = None,
) -> dict[str, object]:
    try:
        flow = get_adapter(harness).approval_flow(managed_install=managed_install)
    except ValueError:
        flow = {}
    return {
        "tier": str(flow.get("tier") or "approval-center"),
        "summary": str(flow.get("summary") or ""),
        "fallback_hint": str(flow.get("fallback_hint") or ""),
        "prompt_channel": str(flow.get("prompt_channel") or "browser"),
        "auto_open_browser": bool(flow.get("auto_open_browser", True)),
    }


def approval_delivery_payload(flow: dict[str, object]) -> dict[str, object]:
    auto_open_browser = bool(flow.get("auto_open_browser"))
    return {
        "destination": "browser" if auto_open_browser else "harness",
        "prompt_channel": str(flow.get("prompt_channel") or "browser"),
        "summary": str(flow.get("summary") or ""),
    }


def wait_for_approval_requests(
    *,
    store: GuardStore,
    request_ids: list[str],
    timeout_seconds: int,
    poll_interval: float = 0.25,
) -> dict[str, object]:
    deadline = time.monotonic() + max(timeout_seconds, 0)
    while True:
        items = [store.get_approval_request(request_id) for request_id in request_ids]
        resolved_items = [item for item in items if isinstance(item, dict) and item.get("status") == "resolved"]
        pending_ids = [
            request_id
            for request_id, item in zip(request_ids, items, strict=True)
            if not isinstance(item, dict) or item.get("status") != "resolved"
        ]
        if not pending_ids:
            return {"resolved": True, "pending_request_ids": [], "items": resolved_items}
        if time.monotonic() >= deadline:
            return {"resolved": False, "pending_request_ids": pending_ids, "items": resolved_items}
        time.sleep(poll_interval)


def _artifact_name(item: dict[str, object], artifact_id: str) -> str:
    name = item.get("artifact_name")
    return str(name) if isinstance(name, str) and name else artifact_id


def _config_path(item: dict[str, object], artifact) -> str:
    if artifact is not None:
        return artifact.config_path
    value = item.get("config_path")
    if isinstance(value, str) and value:
        return value
    return str(Path.cwd())


def _launch_target(artifact, item: dict[str, object]) -> str | None:
    value = item.get("launch_target")
    if isinstance(value, str) and value:
        return value
    if artifact is not None:
        if artifact.url:
            return artifact.url
        if artifact.command:
            parts = [artifact.command, *artifact.args]
            return " ".join(parts)
    return None


def _source_scope(item: dict[str, object], artifact) -> str:
    if artifact is not None:
        return artifact.source_scope
    value = item.get("source_scope")
    if isinstance(value, str) and value:
        return value
    return "project"


def _artifact_type(item: dict[str, object]) -> str:
    value = item.get("artifact_type")
    if isinstance(value, str) and value:
        return value
    return "artifact"


def _workspace_scope_target(item: dict[str, object], artifact) -> str | None:
    config_path = _config_path(item, artifact)
    if not config_path:
        return None
    config_file = Path(config_path)
    parent = config_file.parent
    workspace_root = parent.parent if parent.name.startswith(".") else parent
    workspace_value = str(workspace_root)
    if workspace_value:
        return workspace_value
    return None


def _item_risk_summary(item: dict[str, object], artifact) -> str | None:
    value = item.get("risk_summary")
    if isinstance(value, str) and value:
        return value
    return artifact_risk_summary(artifact) if artifact is not None else None


def _item_risk_signals(item: dict[str, object], artifact) -> tuple[str, ...]:
    value = item.get("risk_signals")
    if isinstance(value, list):
        normalized = tuple(str(signal) for signal in value if isinstance(signal, str) and signal)
        if normalized:
            return normalized
    return artifact_risk_signals(artifact) if artifact is not None else ()


def _item_action_envelope_json(item: dict[str, object]) -> dict[str, object] | None:
    value = item.get("action_envelope_json")
    if not isinstance(value, Mapping):
        return None
    return {str(key): item_value for key, item_value in value.items() if isinstance(key, str)}


def _item_decision_v2_json(item: dict[str, object]) -> dict[str, object] | None:
    value = item.get("decision_v2_json")
    if not isinstance(value, Mapping):
        return None
    return {str(key): item_value for key, item_value in value.items() if isinstance(key, str)}


def _item_scanner_evidence(item: dict[str, object]) -> tuple[dict[str, object], ...]:
    value = item.get("scanner_evidence")
    if not isinstance(value, list | tuple):
        return ()
    return tuple(dict(entry) for entry in value if isinstance(entry, Mapping))


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_runtime_cloud_context(store: GuardStore) -> dict[str, object]:
    credentials = store.get_sync_credentials()
    sync_url = credentials["sync_url"] if credentials is not None else None
    sync_summary = store.get_sync_payload("sync_summary") or {}
    remote_policy = store.get_sync_payload("policy") or {}
    team_policy_pack = store.get_sync_payload("team_policy_pack") or {}
    alert_preferences = store.get_sync_payload("alert_preferences") or {}
    remote_payload_active = any((sync_summary, remote_policy, team_policy_pack, alert_preferences))
    cloud_state = _resolve_runtime_cloud_state(
        sync_configured=credentials is not None,
        sync_completed=bool(sync_summary),
        remote_payload_active=remote_payload_active,
    )
    dashboard_url, inbox_url, fleet_url, connect_url = _resolve_guard_urls(sync_url)
    sync_health = _build_cloud_sync_health(store, credentials is not None, cloud_state)
    return {
        "sync_configured": credentials is not None,
        "cloud_state": cloud_state,
        "cloud_state_label": _runtime_cloud_state_label(cloud_state),
        "cloud_state_detail": _runtime_cloud_state_detail(cloud_state),
        "cloud_sync_health": sync_health,
        "cloud_pairing_state": {
            "state": cloud_state,
            "label": _runtime_cloud_state_label(cloud_state),
            "detail": _runtime_cloud_state_detail(cloud_state),
            "sync_configured": credentials is not None,
            "dashboard_url": dashboard_url,
            "inbox_url": inbox_url,
            "fleet_url": fleet_url,
            "connect_url": connect_url,
        },
        "dashboard_url": dashboard_url,
        "inbox_url": inbox_url,
        "fleet_url": fleet_url,
        "connect_url": connect_url,
    }


def _build_runtime_device_context(store: GuardStore) -> dict[str, object]:
    metadata = store.get_device_metadata()
    return {
        "installation_id": metadata["installation_id"],
        "device_label": metadata["device_label"],
        "local_registered": True,
    }


def _build_latest_connect_state(store: GuardStore, now: str) -> dict[str, object] | None:
    state = store.get_latest_guard_connect_state(now=now)
    if state is None:
        return None
    return {
        "request_id": _optional_string(state.get("request_id")),
        "status": _optional_string(state.get("status")),
        "milestone": _optional_string(state.get("milestone")),
        "reason": _optional_string(state.get("reason")),
        "created_at": _optional_string(state.get("created_at")),
        "updated_at": _optional_string(state.get("updated_at")),
        "expires_at": _optional_string(state.get("expires_at")),
        "completed_at": _optional_string(state.get("completed_at")),
        "proof": _connect_state_proof(state.get("proof")),
    }


def _connect_state_proof(value: object) -> dict[str, object]:
    source = value if isinstance(value, Mapping) else {}
    return {
        "pairing_completed_at": _optional_string(source.get("pairing_completed_at")),
        "first_synced_at": _optional_string(source.get("first_synced_at")),
        "receipts_stored": _non_negative_int(source.get("receipts_stored")),
        "inventory_items": _non_negative_int(source.get("inventory_items")),
        "runtime_session_id": _optional_string(source.get("runtime_session_id")),
        "runtime_session_synced_at": _optional_string(source.get("runtime_session_synced_at")),
    }


def _build_runtime_proof_status(latest_state: dict[str, object] | None) -> dict[str, object]:
    proof = _connect_state_proof(latest_state.get("proof") if latest_state is not None else None)
    if latest_state is None:
        status = "not_connected"
        return _runtime_proof_status_payload(
            state=status,
            label=_runtime_proof_status_label(status),
            detail=_runtime_proof_status_detail(status),
            request_id=None,
            proof=proof,
        )
    status = _runtime_proof_status_name(
        status=_optional_string(latest_state.get("status")),
        milestone=_optional_string(latest_state.get("milestone")),
        proof=proof,
    )
    return _runtime_proof_status_payload(
        state=status,
        label=_runtime_proof_status_label(status),
        detail=_runtime_proof_status_detail(status),
        request_id=_optional_string(latest_state.get("request_id")),
        proof=proof,
    )


def _runtime_proof_status_payload(
    *,
    state: str,
    label: str,
    detail: str,
    request_id: str | None,
    proof: Mapping[str, object],
) -> dict[str, object]:
    return {
        "state": state,
        "label": label,
        "detail": detail,
        "request_id": request_id,
        **proof,
    }


def _runtime_proof_status_name(
    *,
    status: str | None,
    milestone: str | None,
    proof: Mapping[str, object],
) -> str:
    if milestone == "first_sync_succeeded" or proof.get("first_synced_at"):
        return "synced"
    if milestone == "sync_not_available":
        return "sync_unavailable"
    if status == "retry_required" or milestone == "first_sync_failed":
        return "failed"
    if milestone == "first_sync_pending":
        return "pending"
    if milestone == "expired" or status == "expired":
        return "expired"
    if milestone == "waiting_for_browser" or status == "waiting":
        return "waiting"
    return "not_connected"


def _runtime_proof_status_label(state: str) -> str:
    labels = {
        "synced": "First proof synced",
        "sync_unavailable": "Local connected, cloud sync gated",
        "failed": "First proof needs retry",
        "pending": "First proof pending",
        "expired": "Pairing expired",
        "waiting": "Waiting for browser pairing",
        "not_connected": "Cloud proof not started",
    }
    return labels.get(state, "Cloud proof not started")


def _runtime_proof_status_detail(state: str) -> str:
    details = {
        "synced": "This device completed its first Guard Cloud proof sync.",
        "sync_unavailable": "Local Guard is connected. Shared cloud sync needs a paid Guard plan.",
        "failed": "Run hol-guard connect again to finish first proof sync.",
        "pending": "Browser pairing finished. First proof sync has not completed yet.",
        "expired": "The pairing link expired. Run hol-guard connect again.",
        "waiting": "Open the pairing link to register this local Guard device.",
        "not_connected": "Connect Guard Cloud to sync this device proof.",
    }
    return details.get(state, "Connect Guard Cloud to sync this device proof.")


def _build_cloud_sync_health(store: GuardStore, sync_configured: bool, cloud_state: str) -> dict[str, object]:
    pending_events = store.count_guard_events_v1(uploaded=False)
    event_summary = store.get_sync_payload("guard_events_v1_summary") or {}
    sync_summary = store.get_sync_payload("sync_summary") or {}
    runtime_summary = store.get_sync_payload("runtime_session_summary") or {}
    last_synced_at = _latest_sync_timestamp(
        event_summary.get("synced_at"),
        sync_summary.get("synced_at"),
        runtime_summary.get("synced_at"),
    )
    if not sync_configured:
        state = "disabled"
    elif isinstance(event_summary, dict) and event_summary.get("status") == "failed":
        state = "failed"
    elif (
        isinstance(event_summary, dict)
        and event_summary.get("sync_skipped") is True
        and event_summary.get("sync_reason") == "guard_events_endpoint_unavailable"
    ):
        state = "degraded"
    elif last_synced_at is not None and _timestamp_is_stale(last_synced_at):
        state = "stale"
    elif pending_events > 0 or cloud_state == "paired_waiting":
        state = "pending"
    else:
        state = "healthy"
    return {
        "state": state,
        "label": _cloud_sync_health_label(state),
        "detail": _cloud_sync_health_detail(state, pending_events=pending_events),
        "pending_events": pending_events,
        "last_synced_at": last_synced_at,
        "next_retry_after": event_summary.get("next_retry_after") if isinstance(event_summary, dict) else None,
    }


def _latest_sync_timestamp(*values: object) -> str | None:
    parsed_values: list[tuple[datetime, str]] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        parsed = _parse_timestamp(value)
        if parsed is not None:
            parsed_values.append((parsed, value))
    if not parsed_values:
        return None
    return max(parsed_values, key=lambda item: item[0])[1]


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _timestamp_is_stale(value: str) -> bool:
    parsed = _parse_timestamp(value)
    if parsed is None:
        return False
    return datetime.now(timezone.utc) - parsed > timedelta(hours=24)


def _cloud_sync_health_label(state: str) -> str:
    labels = {
        "healthy": "Cloud sync healthy",
        "pending": "Cloud sync pending",
        "failed": "Cloud sync needs attention",
        "degraded": "Cloud sync degraded",
        "disabled": "Cloud sync disabled",
        "stale": "Cloud sync stale",
    }
    return labels.get(state, "Cloud sync pending")


def _cloud_sync_health_detail(state: str, *, pending_events: int) -> str:
    if state == "healthy":
        return "Guard Cloud has the latest local proof from this machine."
    if state == "failed":
        return "The latest Cloud upload failed. HOL Guard kept local protection active and will retry."
    if state == "degraded":
        return "Cloud accepted legacy sync, but v1 Guard event ingest is unavailable. Local protection stayed active."
    if state == "disabled":
        return "Local protection is active. Connect Cloud when you want shared team proof."
    if state == "stale":
        return "Cloud has not seen fresh local proof recently. Keep this runtime open or run sync again."
    if pending_events == 1:
        return "One local proof event is queued for the next Cloud sync."
    if pending_events > 1:
        return f"{pending_events} local proof events are queued for the next Cloud sync."
    return "Waiting for the first shared Cloud proof from this machine."


def _resolve_runtime_cloud_state(*, sync_configured: bool, sync_completed: bool, remote_payload_active: bool) -> str:
    if not sync_configured:
        return "local_only"
    if sync_completed or remote_payload_active:
        return "paired_active"
    return "paired_waiting"


def _runtime_cloud_state_label(cloud_state: str) -> str:
    labels = {
        "local_only": "Local only",
        "paired_waiting": "Connected",
        "paired_active": "Connected",
    }
    return labels.get(cloud_state, "Local only")


def _runtime_cloud_state_detail(cloud_state: str) -> str:
    if cloud_state == "paired_waiting":
        return (
            "This machine is connected to Guard Cloud, but the first shared proof has not landed yet. "
            "Open Fleet while the first sync settles."
        )
    if cloud_state == "paired_active":
        return (
            "This machine is connected to Guard Cloud. Open Home, Inbox, or Fleet in the portal "
            "to continue with shared review and proof."
        )
    return "Guard is protecting this machine locally. Connect when you want Home, Inbox, Fleet, and shared team memory."


def _resolve_guard_urls(sync_url: object) -> tuple[str, str, str, str]:
    if not isinstance(sync_url, str) or not sync_url:
        return GUARD_DASHBOARD_URL, GUARD_INBOX_URL, GUARD_FLEET_URL, GUARD_CONNECT_URL
    parsed = urlparse(sync_url)
    if not parsed.scheme or not parsed.netloc:
        return GUARD_DASHBOARD_URL, GUARD_INBOX_URL, GUARD_FLEET_URL, GUARD_CONNECT_URL
    origin = f"{parsed.scheme}://{parsed.netloc}"
    dashboard_url = f"{origin}/guard"
    return (
        dashboard_url,
        f"{dashboard_url}/inbox",
        f"{dashboard_url}/fleet",
        f"{dashboard_url}/connect",
    )


def _resolve_runtime_headline_state(
    *,
    pending_count: int,
    runtime_state: dict[str, object] | None,
    cloud_state: str,
) -> str:
    if runtime_state is None:
        return "setup"
    if pending_count > 0:
        return "blocked"
    if cloud_state == "local_only":
        return "local_only"
    if cloud_state == "paired_waiting":
        return "connected"
    return "protected"


def _runtime_headline_label(headline_state: str) -> str:
    labels = {
        "setup": "Setup required",
        "protected": "Protected",
        "blocked": "Blocked",
        "local_only": "Local only",
        "connected": "Connected",
    }
    return labels.get(headline_state, "Local only")


def _runtime_headline_detail(headline_state: str) -> str:
    details = {
        "setup": "The local Guard runtime is offline. Start the daemon or rerun hol-guard bootstrap.",
        "protected": "This machine is protected and the local queue is clear.",
        "blocked": "A blocked launch is waiting for review in the current request queue.",
        "local_only": "This machine is protected locally and can connect later when shared memory matters.",
        "connected": "This machine is connected to Guard Cloud and waiting for the first shared proof to appear.",
    }
    return details.get(headline_state, "This machine is protected locally.")


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _non_negative_int(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, str) and value.strip():
        try:
            return max(0, int(value.strip()))
        except ValueError:
            return 0
    return 0


def _queue_risk_summary(queued: list[dict[str, object]]) -> str:
    signals: list[str] = []
    for item in queued:
        for signal in _string_list(item.get("risk_signals")):
            if signal not in signals:
                signals.append(signal)
    if len(signals) == 0:
        return "No obvious secret-access or network signal was detected."
    if len(signals) == 1:
        return f"Risk signal: {signals[0]}."
    return f"Risk signals: {signals[0]}, {signals[1]}."
