"""Approval queue orchestration for local Guard reviews."""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypeGuard
from urllib.parse import ParseResult, parse_qsl, urlencode, urlparse, urlunparse

from .adapters import get_adapter
from .adapters.base import HarnessContext
from .approval_gate import ApprovalGateGrant, ApprovalGateInput, require_approval_decision
from .cli.connect_flow import (
    connect_retry_refresh_race_from_reason,
    resolve_guard_cloud_repair_detail,
    resolve_guard_cloud_state,
)
from .config import load_guard_config
from .daemon.manager import load_guard_daemon_auth_token
from .desktop_notifications import (
    DesktopApprovalNotification,
    notify_pending_approval_once,
)
from .incident import build_incident_context
from .local_dashboard_session import build_local_dashboard_session_token
from .local_supply_chain import build_local_supply_chain_posture
from .models import (
    DECISION_SCOPE_VALUES,
    GUARD_ACTION_VALUES,
    DecisionScope,
    GuardAction,
    GuardApprovalRequest,
    HarnessDetection,
    PolicyDecision,
)
from .risk import artifact_risk_signals, artifact_risk_summary
from .store import GuardStore, _runtime_scoped_exact_match_key

GUARD_COMMAND = "hol-guard"
GUARD_DASHBOARD_URL = "https://hol.org/guard"
GUARD_INBOX_URL = f"{GUARD_DASHBOARD_URL}/inbox"
GUARD_FLEET_URL = f"{GUARD_DASHBOARD_URL}/protect"
GUARD_CONNECT_URL = f"{GUARD_DASHBOARD_URL}/connect"
_WORKSPACE_SCOPED_RUNTIME_ARTIFACT_TYPES = frozenset(
    {
        "file_read_request",
        "package_request",
        "prompt_request",
        "tool_action_request",
    }
)


class ApprovalRequestNotFoundError(ValueError):
    """Raised when an approval request ID does not exist."""


class ApprovalRequestAlreadyResolvedError(ValueError):
    """Raised when an approval request was already resolved."""


def build_approval_request_url(approval_center_url: str, request_id: str) -> str:
    """Build the canonical local dashboard deep link for one approval request."""

    return f"{approval_center_url.rstrip('/')}/requests/{request_id.strip()}"


def build_approval_browser_url(approval_url: str | None, *, auth_token: str | None) -> str | None:
    """Build a browser-openable approval URL with a scoped Guard session token."""

    if not approval_url or auth_token is None:
        return approval_url
    parsed = urlparse(approval_url)
    fragment_pairs = [
        (key, value) for key, value in parse_qsl(parsed.fragment, keep_blank_values=True) if key != "guard-token"
    ]
    fragment_pairs.append(
        (
            "guard-token",
            build_local_dashboard_session_token(
                auth_token=auth_token,
                surface="approval-center",
            ),
        )
    )
    return urlunparse(parsed._replace(fragment=urlencode(fragment_pairs)))


def _normalize_harness_slug(harness: str | None) -> str | None:
    if not isinstance(harness, str):
        return None
    normalized = harness.strip().lower()
    if normalized in {"claude", "claude-code"}:
        return "claude-code"
    return normalized or None


def _is_guard_action(value: object) -> TypeGuard[GuardAction]:
    return isinstance(value, str) and value in GUARD_ACTION_VALUES


def _is_decision_scope(value: object) -> TypeGuard[DecisionScope]:
    return isinstance(value, str) and value in DECISION_SCOPE_VALUES


def _queued_request_dicts(queued: Sequence[object]) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for item in queued:
        if isinstance(item, Mapping):
            items.append(dict(item))
    return items


def primary_approval_request(
    queued: Sequence[object],
    *,
    harness: str | None = None,
    request_id: str | None = None,
    artifact_id: str | None = None,
) -> dict[str, object] | None:
    """Return the approval request created for this blocked action."""

    items = _queued_request_dicts(queued)
    if not items:
        return None

    bound_request_id = _string_or_none(request_id)
    if bound_request_id is not None:
        for item in items:
            if _string_or_none(item.get("request_id")) == bound_request_id:
                return item
        return None

    bound_artifact_id = _string_or_none(artifact_id)
    if bound_artifact_id is not None:
        for item in reversed(items):
            if _string_or_none(item.get("artifact_id")) == bound_artifact_id:
                return item

    if len(items) == 1:
        return items[0]

    normalized_harness = _normalize_harness_slug(harness)
    if normalized_harness is not None:
        for item in reversed(items):
            item_harness = _normalize_harness_slug(str(item.get("harness") or ""))
            if item_harness == normalized_harness:
                return item

    return None


def primary_approval_url(
    queued: Sequence[object],
    *,
    harness: str | None = None,
    approval_center_url: str | None = None,
    request_id: str | None = None,
    artifact_id: str | None = None,
) -> str | None:
    request = primary_approval_request(
        queued,
        harness=harness,
        request_id=request_id,
        artifact_id=artifact_id,
    )
    if request is None:
        return None
    approval_url = request.get("approval_url")
    if isinstance(approval_url, str) and approval_url.strip():
        return _canonical_local_approval_url(
            approval_url.strip().replace("/approvals/", "/requests/"),
            approval_center_url=approval_center_url,
        )
    resolved_request_id = request.get("request_id")
    if isinstance(resolved_request_id, str) and resolved_request_id.strip() and isinstance(approval_center_url, str):
        center = approval_center_url.strip()
        if center:
            return build_approval_request_url(center, resolved_request_id.strip())
    return None


def _canonical_local_approval_url(approval_url: str, *, approval_center_url: str | None) -> str:
    if not isinstance(approval_center_url, str) or not approval_center_url.strip():
        return approval_url
    try:
        parsed_approval = urlparse(approval_url)
        parsed_center = urlparse(approval_center_url.strip())
    except ValueError:
        return approval_url
    loopback_hosts = {"127.0.0.1", "::1", "localhost"}
    approval_host = _parsed_url_host(parsed_approval)
    center_host = _parsed_url_host(parsed_center)
    if parsed_approval.scheme not in {"http", "https"} or approval_host not in loopback_hosts:
        return approval_url
    if parsed_center.scheme not in {"http", "https"} or center_host not in loopback_hosts:
        return approval_url
    return urlunparse(
        parsed_approval._replace(
            scheme=parsed_center.scheme,
            netloc=parsed_center.netloc,
        )
    )


def _parsed_url_host(parsed: ParseResult) -> str:
    host_port = parsed.netloc.rsplit("@", 1)[-1]
    if host_port.startswith("["):
        host, _separator, _rest = host_port[1:].partition("]")
        return host
    if host_port.count(":") == 1:
        host, _port = host_port.rsplit(":", 1)
        return host
    return host_port


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
    artifacts = evaluation.get("artifacts")
    if not isinstance(artifacts, list):
        return queued
    for item in artifacts:
        if not isinstance(item, dict):
            continue
        policy_action = item.get("policy_action")
        if not _is_guard_action(policy_action) or policy_action not in {
            "block",
            "sandbox-required",
            "require-reapproval",
        }:
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
            policy_action=policy_action,
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
            policy_action=policy_action,
            recommended_scope="publisher" if artifact is not None and artifact.publisher else "artifact",
            changed_fields=tuple(_string_list(item.get("changed_fields"))),
            source_scope=_source_scope(item, artifact),
            config_path=_config_path(item, artifact),
            launch_target=launch_target,
            transport=artifact.transport if artifact is not None else None,
            review_command=f"{GUARD_COMMAND} approvals approve {request_id}",
            approval_url=build_approval_request_url(approval_center_url, request_id),
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
        created_new_request = persisted_request_id == request.request_id
        if persisted_request_id != request.request_id:
            request = replace(
                request,
                request_id=persisted_request_id,
                review_command=f"{GUARD_COMMAND} approvals approve {persisted_request_id}",
                approval_url=build_approval_request_url(approval_center_url, persisted_request_id),
            )
        if created_new_request:
            _record_created_event(store, request, timestamp)
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
    approval_gate_input: ApprovalGateInput | None = None,
    approval_gate_grant: ApprovalGateGrant | None = None,
    persist_policy: bool = True,
) -> dict[str, object]:
    request = store.get_approval_request(request_id)
    if request is None:
        raise ApprovalRequestNotFoundError(f"Unknown approval request: {request_id}")
    if request["status"] != "pending":
        raise ApprovalRequestAlreadyResolvedError(f"Approval request already resolved: {request_id}")
    if not _is_decision_scope(scope):
        raise ValueError(f"Unsupported approval scope: {scope}")
    if scope == "workspace" and not workspace:
        raise ValueError(f"Approval request {request_id} requires --workspace for workspace scope.")
    if scope == "publisher" and _string_or_none(request.get("publisher")) is None:
        raise ValueError(f"Approval request {request_id} has no publisher scope to approve.")
    workspace_artifact_id, workspace_artifact_hash = _workspace_policy_artifact_keys(request, scope)
    request_artifact_id = _string_or_none(request.get("artifact_id"))
    request_artifact_hash = _string_or_none(request.get("artifact_hash"))
    request_publisher = _string_or_none(request.get("publisher"))
    scoped_artifact_id = request_artifact_id if scope in {"artifact", "harness", "global"} else workspace_artifact_id
    scoped_artifact_hash = request_artifact_hash if scope == "artifact" else workspace_artifact_hash
    artifact_runtime_exact_match_key = _artifact_scope_runtime_exact_match_key(request, scope)
    if artifact_runtime_exact_match_key is not None:
        scoped_artifact_hash = artifact_runtime_exact_match_key
    broad_runtime_exact_match_key = _broad_runtime_exact_match_key(request, scope)
    if broad_runtime_exact_match_key is not None:
        scoped_artifact_hash = broad_runtime_exact_match_key
    decision = PolicyDecision(
        harness="*" if scope == "global" else str(request["harness"]),
        scope=scope,
        action="allow" if action == "allow" else "block",
        artifact_id=scoped_artifact_id,
        artifact_hash=scoped_artifact_hash,
        workspace=workspace if scope == "workspace" else None,
        publisher=request_publisher if scope == "publisher" else None,
        reason=reason,
    )
    resolved_at = now or _now()
    resolved_gate_grant = require_approval_decision(
        store.guard_home,
        action=decision.action,
        scope=scope,
        approval_gate_input=approval_gate_input,
        approval_gate_grant=approval_gate_grant,
        now=resolved_at,
    )
    if persist_policy:
        store.upsert_policy(decision, resolved_at, approval_gate_grant=resolved_gate_grant)
    resolution_harness = None if scope == "global" else str(request["harness"])
    if return_queue_result:
        result = store.resolve_request_with_queue_result(
            request_id,
            resolution_action=action,
            resolution_scope=scope,
            reason=reason,
            resolved_at=resolved_at,
            approval_gate_grant=resolved_gate_grant,
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
                approval_gate_grant=resolved_gate_grant,
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
            approval_gate_grant=resolved_gate_grant,
        )
    if request_id not in resolved_ids:
        store.resolve_approval_request(
            request_id,
            resolution_action=action,
            resolution_scope=scope,
            reason=reason,
            resolved_at=resolved_at,
            approval_gate_grant=resolved_gate_grant,
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


def _artifact_scope_runtime_exact_match_key(request: Mapping[str, object], scope: str) -> str | None:
    if scope != "artifact" or request.get("artifact_type") not in _WORKSPACE_SCOPED_RUNTIME_ARTIFACT_TYPES:
        return None
    artifact_id = request.get("artifact_id")
    return _runtime_scoped_exact_match_key(artifact_id) if isinstance(artifact_id, str) else None


def _broad_runtime_exact_match_key(request: Mapping[str, object], scope: str) -> str | None:
    if scope not in {"harness", "global"}:
        return None
    if request.get("artifact_type") not in _WORKSPACE_SCOPED_RUNTIME_ARTIFACT_TYPES:
        return None
    artifact_id = request.get("artifact_id")
    if not isinstance(artifact_id, str) or not artifact_id:
        return None
    return _runtime_scoped_exact_match_key(artifact_id)


def _append_guard_token_to_url(url: str, auth_token: str) -> str:
    """Append a fresh guard-token fragment to an approval URL."""
    parsed = urlparse(url)
    fragment_pairs = [
        (key, value) for key, value in parse_qsl(parsed.fragment, keep_blank_values=True) if key != "guard-token"
    ]
    fragment_pairs.append(
        (
            "guard-token",
            build_local_dashboard_session_token(
                auth_token=auth_token,
                surface="approval-center",
            ),
        )
    )
    return urlunparse(parsed._replace(fragment=urlencode(fragment_pairs)))


def _notify_pending_approval(*, store: GuardStore, request: GuardApprovalRequest) -> None:
    try:
        config = load_guard_config(
            store.guard_home,
            Path(request.workspace) if request.workspace is not None else None,
        )
    except Exception:
        config = None
    if config is not None and not config.desktop_notifications:
        return
    if store.approval_desktop_notified_at(request.request_id) is not None:
        return
    auth_token = load_guard_daemon_auth_token(store.guard_home)
    approval_url = request.approval_url
    if auth_token:
        approval_url = _append_guard_token_to_url(approval_url, auth_token)
    notify_pending_approval_once(
        DesktopApprovalNotification(
            request_id=request.request_id,
            title="HOL Guard needs approval",
            message=_approval_notification_message(request),
            approval_url=approval_url,
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


def _record_created_event(store: GuardStore, request: GuardApprovalRequest, created_at: str) -> None:
    store.add_event(
        "approval.created",
        {
            "request_id": request.request_id,
            "harness": request.harness,
            "artifact_id": request.artifact_id,
            "artifact_name": request.artifact_name,
            "artifact_type": request.artifact_type,
            "policy_action": request.policy_action,
            "recommended_scope": request.recommended_scope,
            "source_scope": request.source_scope,
            "workspace": request.workspace,
            "publisher": request.publisher,
        },
        created_at,
    )


def _refresh_queue_result(
    store: GuardStore,
    result: dict[str, object],
    resolved_scope_ids: list[str],
) -> None:
    page = store.list_pending_approval_summaries(limit=10)
    next_request = store.get_next_pending_request()
    remaining_count = _non_negative_int(page.get("total_pending_count"))
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
    request_id: str | None = None,
    artifact_id: str | None = None,
    review_url: str | None = None,
) -> str:
    del context
    flow = approval_prompt_flow(harness, managed_install=managed_install)
    count = len(queued)
    risk_summary = _queue_risk_summary(queued)
    resolved_review_url = review_url or (
        primary_approval_url(
            queued,
            harness=harness,
            approval_center_url=approval_center_url,
            request_id=request_id,
            artifact_id=artifact_id,
        )
        or approval_center_url
    )
    return (
        f"Guard queued {count} approval request{'s' if count != 1 else ''} for {harness}. "
        f"{flow['summary']} "
        f"Review them in the Guard approval center at {resolved_review_url}. "
        f"{risk_summary} "
        f"{flow['fallback_hint']}"
    )


def first_approval_url(
    queued: Sequence[object],
    *,
    harness: str | None = None,
    approval_center_url: str | None = None,
    request_id: str | None = None,
    artifact_id: str | None = None,
) -> str | None:
    return primary_approval_url(
        queued,
        harness=harness,
        approval_center_url=approval_center_url,
        request_id=request_id,
        artifact_id=artifact_id,
    )


def _primary_request_id_candidates(
    payload: Mapping[str, object],
    *,
    request_id: str | None = None,
) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()

    def add(value: object) -> None:
        normalized = _string_or_none(value)
        if normalized is not None and normalized not in seen:
            seen.add(normalized)
            candidates.append(normalized)

    add(request_id)
    add(payload.get("primary_approval_request_id"))
    operation_ids = payload.get("approval_request_ids")
    if isinstance(operation_ids, list):
        for item in operation_ids:
            add(item)
    operation = payload.get("operation")
    if isinstance(operation, Mapping):
        nested_ids = operation.get("approval_request_ids")
        if isinstance(nested_ids, list):
            for item in nested_ids:
                add(item)
    return candidates


def _queued_request_ids(queued: Sequence[object]) -> set[str]:
    request_ids: set[str] = set()
    for item in queued:
        if not isinstance(item, Mapping):
            continue
        normalized = _string_or_none(item.get("request_id"))
        if normalized is not None:
            request_ids.add(normalized)
    return request_ids


def attach_primary_approval_link(
    payload: dict[str, object],
    *,
    harness: str | None = None,
    approval_center_url: str | None = None,
    request_id: str | None = None,
    artifact_id: str | None = None,
) -> None:
    """Bind primary approval fields to the request created by this block."""

    queued = payload.get("approval_requests")
    if not isinstance(queued, list):
        return

    bound_artifact_id = _string_or_none(artifact_id)
    if bound_artifact_id is None:
        bound_artifact_id = _string_or_none(payload.get("artifact_id"))

    queued_ids = _queued_request_ids(queued)
    bound_request_id = next(
        (
            candidate
            for candidate in _primary_request_id_candidates(payload, request_id=request_id)
            if candidate in queued_ids
        ),
        None,
    )

    primary = None
    if bound_artifact_id is not None:
        primary = primary_approval_request(
            queued,
            harness=harness,
            artifact_id=bound_artifact_id,
        )
    if primary is None:
        primary = primary_approval_request(
            queued,
            harness=harness,
            request_id=bound_request_id,
            artifact_id=bound_artifact_id,
        )
    if primary is None:
        return
    resolved_request_id = _string_or_none(primary.get("request_id"))
    if resolved_request_id is not None:
        payload["primary_approval_request_id"] = resolved_request_id
    review_url = primary_approval_url(
        queued,
        harness=harness,
        approval_center_url=approval_center_url,
        request_id=resolved_request_id,
        artifact_id=bound_artifact_id,
    )
    if review_url is not None:
        payload["primary_approval_url"] = review_url


def build_runtime_snapshot(
    *,
    store: GuardStore,
    approval_center_url: str | None,
    now: str | None = None,
    request_limit: int = 200,
    receipt_limit: int = 25,
    active_request_id: str | None = None,
    include_items: bool = True,
) -> dict[str, object]:
    queue_page = store.list_pending_approval_summaries(limit=1)
    queue_items = queue_page["items"] if isinstance(queue_page["items"], list) else []
    pending_count = _non_negative_int(queue_page.get("total_pending_count"))
    pending_requests = store.list_approval_requests(limit=request_limit) if include_items else []
    active_request = store.get_approval_request(active_request_id) if active_request_id else None
    active_is_pending = active_request is not None and active_request.get("status") == "pending"
    first_request_id = str(queue_items[0]["request_id"]) if queue_items else None
    next_request_id = active_request_id if active_is_pending else first_request_id
    latest_receipts = store.list_receipts(limit=receipt_limit)
    snapshot_now = now or _now()
    config = load_guard_config(store.guard_home)
    latest_connect_state = _build_latest_connect_state(store, snapshot_now)
    oauth_storage_health = store.get_oauth_local_credential_health()
    cloud_context = _build_runtime_cloud_context(
        store,
        latest_connect_state=latest_connect_state,
        oauth_storage_health=oauth_storage_health,
    )
    headline_state = _resolve_runtime_headline_state(
        pending_count=pending_count,
        runtime_state=store.get_runtime_state(),
        cloud_state=str(cloud_context["cloud_state"]),
    )
    return {
        "generated_at": snapshot_now,
        "approval_center_url": approval_center_url,
        "runtime_state": store.get_runtime_state(),
        "oauth_storage_health": oauth_storage_health,
        "device": _build_runtime_device_context(store),
        "latest_connect_state": latest_connect_state,
        "proof_status": _build_runtime_proof_status(latest_connect_state),
        "pending_count": pending_count,
        "queue_summary": {
            "active_request_id": active_request_id if active_is_pending else None,
            "next_request_id": next_request_id,
            "remaining_pending_count": pending_count,
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
        "supply_chain": build_local_supply_chain_posture(store, config, now=snapshot_now),
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


def _build_runtime_cloud_context(
    store: GuardStore,
    latest_connect_state: dict[str, object] | None,
    *,
    oauth_storage_health: dict[str, object] | None = None,
) -> dict[str, object]:
    cloud_profile = store.get_cloud_sync_profile()
    if oauth_storage_health is None:
        oauth_storage_health = store.get_oauth_local_credential_health()
    oauth_repair_required = (
        bool(oauth_storage_health.get("configured")) and oauth_storage_health.get("state") == "degraded"
    )
    connect_retry_required = _connect_retry_required(latest_connect_state)
    connect_retry_refresh_race = _connect_retry_refresh_race(latest_connect_state)
    sync_url = cloud_profile["sync_url"] if cloud_profile is not None else None
    sync_summary = store.get_sync_payload("sync_summary") or {}
    remote_policy = store.get_sync_payload("policy") or {}
    team_policy_pack = store.get_sync_payload("team_policy_pack") or {}
    alert_preferences = store.get_sync_payload("alert_preferences") or {}
    policy_bundle = _sync_payload_dict(store, "policy_bundle")
    policy_bundle_last_error = _sync_payload_dict(store, "policy_bundle_last_error")
    acknowledgement = policy_bundle.get("acknowledgement")
    cloud_policy_last_ack_at = (
        _optional_string(acknowledgement.get("acknowledgedAt")) if isinstance(acknowledgement, dict) else None
    )
    remote_payload_active = any((sync_summary, remote_policy, team_policy_pack, alert_preferences))
    cloud_state = resolve_guard_cloud_state(
        sync_configured=cloud_profile is not None,
        sync_completed=bool(sync_summary),
        remote_payload_active=remote_payload_active,
        oauth_repair_required=oauth_repair_required,
        connect_retry_required=connect_retry_required,
    )
    dashboard_url, inbox_url, fleet_url, connect_url = _resolve_guard_urls(sync_url)
    sync_health = _build_cloud_sync_health(
        store,
        cloud_profile is not None,
        cloud_state,
        oauth_repair_required=oauth_repair_required,
        connect_retry_required=connect_retry_required,
        connect_retry_refresh_race=connect_retry_refresh_race,
    )
    return {
        "sync_configured": cloud_profile is not None,
        "cloud_state": cloud_state,
        "cloud_state_label": _runtime_cloud_state_label(cloud_state),
        "cloud_state_detail": _runtime_cloud_state_detail(
            cloud_state,
            oauth_repair_required=oauth_repair_required,
            connect_retry_required=connect_retry_required,
            connect_retry_refresh_race=connect_retry_refresh_race,
            shared_proof_recorded=bool(sync_summary) or remote_payload_active,
        ),
        "cloud_sync_health": sync_health,
        "cloud_pairing_state": {
            "state": cloud_state,
            "label": _runtime_cloud_state_label(cloud_state),
            "detail": _runtime_cloud_state_detail(
                cloud_state,
                oauth_repair_required=oauth_repair_required,
                connect_retry_required=connect_retry_required,
                connect_retry_refresh_race=connect_retry_refresh_race,
                shared_proof_recorded=bool(sync_summary) or remote_payload_active,
            ),
            "sync_configured": cloud_profile is not None,
            "dashboard_url": dashboard_url,
            "inbox_url": inbox_url,
            "fleet_url": fleet_url,
            "connect_url": connect_url,
        },
        "dashboard_url": dashboard_url,
        "inbox_url": inbox_url,
        "fleet_url": fleet_url,
        "connect_url": connect_url,
        "cloud_policy_bundle_hash": _optional_string(policy_bundle.get("bundleHash")),
        "cloud_policy_bundle_version": _optional_string(policy_bundle.get("bundleVersion")),
        "cloud_policy_rollout_state": _optional_string(policy_bundle.get("rolloutState")),
        "cloud_policy_sync_error": _optional_string(policy_bundle_last_error.get("reason")),
        "cloud_policy_last_ack_at": cloud_policy_last_ack_at,
        "team_policy_active": bool(team_policy_pack),
    }


def _sync_payload_dict(store: GuardStore, key: str) -> dict[str, object]:
    payload = store.get_sync_payload(key) or {}
    return payload if isinstance(payload, dict) else {}


def _build_runtime_device_context(store: GuardStore) -> dict[str, object]:
    metadata = store.get_device_metadata()
    return {
        "installation_id": metadata["installation_id"],
        "device_label": metadata["device_label"],
        "local_registered": True,
    }


def _build_latest_connect_state(store: GuardStore, now: str) -> dict[str, object] | None:
    state = store.get_effective_guard_connect_state(now=now)
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
        reason=_optional_string(latest_state.get("reason")),
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
    reason: str | None,
    proof: Mapping[str, object],
) -> str:
    if status == "retry_required" or milestone == "first_sync_failed":
        if connect_retry_refresh_race_from_reason(reason):
            return "stalled"
        return "failed"
    if milestone == "first_sync_pending":
        return "pending"
    if milestone == "expired" or status == "expired":
        return "expired"
    if milestone == "waiting_for_browser" or status == "waiting":
        return "waiting"
    if milestone == "first_sync_succeeded" or proof.get("first_synced_at"):
        return "synced"
    if milestone == "sync_not_available":
        return "sync_unavailable"
    return "not_connected"


def _runtime_proof_status_label(state: str) -> str:
    labels = {
        "synced": "First proof synced",
        "sync_unavailable": "Local connected, cloud sync gated",
        "failed": "First proof needs retry",
        "stalled": "First proof stalled",
        "pending": "First proof pending",
        "expired": "Sign-in expired",
        "waiting": "Waiting for browser sign-in",
        "not_connected": "Cloud proof not started",
    }
    return labels.get(state, "Cloud proof not started")


def _runtime_proof_status_detail(state: str) -> str:
    details = {
        "synced": "This device completed its first Guard Cloud proof sync.",
        "sync_unavailable": "Local Guard is connected. Shared cloud sync needs a paid Guard plan.",
        "failed": "Guard Cloud sign-in on this machine needs repair. Run hol-guard connect again.",
        "stalled": (
            "Local protection stays active. The first shared Guard Cloud proof stalled after a refresh-token race. "
            "Run hol-guard connect once on this machine when you want shared proof restored."
        ),
        "pending": (
            "Browser sign-in finished. Local Guard will retry the first proof sync automatically "
            "while the daemon is running, or you can run hol-guard sync now."
        ),
        "expired": "The sign-in link expired. Run hol-guard connect again.",
        "waiting": "Open the sign-in link to register this local Guard device.",
        "not_connected": "Connect Guard Cloud to sync this device proof.",
    }
    return details.get(state, "Connect Guard Cloud to sync this device proof.")


def _connect_retry_required(latest_state: dict[str, object] | None) -> bool:
    if latest_state is None:
        return False
    status = _optional_string(latest_state.get("status"))
    milestone = _optional_string(latest_state.get("milestone"))
    return status == "retry_required" or milestone == "first_sync_failed"


def _connect_retry_refresh_race(latest_state: dict[str, object] | None) -> bool:
    if latest_state is None or not _connect_retry_required(latest_state):
        return False
    return connect_retry_refresh_race_from_reason(_optional_string(latest_state.get("reason")))


def _build_cloud_sync_health(
    store: GuardStore,
    sync_configured: bool,
    cloud_state: str,
    *,
    oauth_repair_required: bool = False,
    connect_retry_required: bool = False,
    connect_retry_refresh_race: bool = False,
) -> dict[str, object]:
    pending_events = store.count_guard_events_v1(uploaded=False)
    event_summary = _sync_payload_dict(store, "guard_events_v1_summary")
    sync_summary = _sync_payload_dict(store, "sync_summary")
    runtime_summary = _sync_payload_dict(store, "runtime_session_summary")
    last_synced_at = _latest_sync_timestamp(
        event_summary.get("synced_at"),
        sync_summary.get("synced_at"),
        runtime_summary.get("synced_at"),
    )
    if oauth_repair_required or connect_retry_required:
        state = "failed"
    elif not sync_configured:
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
        "detail": _cloud_sync_health_detail(
            state,
            pending_events=pending_events,
            oauth_repair_required=oauth_repair_required,
            connect_retry_required=connect_retry_required,
            connect_retry_refresh_race=connect_retry_refresh_race,
        ),
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


def _cloud_sync_health_detail(
    state: str,
    *,
    pending_events: int,
    oauth_repair_required: bool = False,
    connect_retry_required: bool = False,
    connect_retry_refresh_race: bool = False,
) -> str:
    if state == "healthy":
        return "Guard Cloud has the latest local proof from this machine."
    if state == "failed":
        if connect_retry_refresh_race:
            return (
                "Local protection is active. The first shared Guard Cloud proof stalled after a refresh-token race. "
                "Run hol-guard connect once to mint a fresh Cloud refresh token."
            )
        if oauth_repair_required or connect_retry_required:
            return (
                "Guard Cloud authorization on this machine needs repair. Run hol-guard connect again to restore sync."
            )
        return (
            "Guard Cloud did not accept the last upload. Guard will retry automatically, "
            "or run hol-guard sync to try again now."
        )
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


def _runtime_cloud_state_label(cloud_state: str) -> str:
    labels = {
        "local_only": "Local only",
        "paired_waiting": "Connected",
        "paired_active": "Connected",
    }
    return labels.get(cloud_state, "Local only")


def _runtime_cloud_state_detail(
    cloud_state: str,
    *,
    oauth_repair_required: bool = False,
    connect_retry_required: bool = False,
    connect_retry_refresh_race: bool = False,
    shared_proof_recorded: bool = False,
) -> str:
    if oauth_repair_required:
        return (
            "Guard Cloud sign-in on this machine is incomplete. "
            "Run hol-guard connect again to repair local authorization and resume sync."
        )
    if connect_retry_refresh_race:
        return (
            "This machine stays locally protected. "
            "The first shared Guard Cloud proof stalled after a refresh-token race. "
            "Run hol-guard connect once when you want shared proof restored."
        )
    if connect_retry_required:
        return resolve_guard_cloud_repair_detail(
            shared_proof_recorded=shared_proof_recorded,
            first_sync_message=(
                "Guard Cloud connection on this machine needs repair before the first shared proof can land. "
                "Run hol-guard connect again."
            ),
            resume_message=(
                "Guard Cloud connection on this machine needs repair before shared proof can resume. "
                "Run hol-guard connect again."
            ),
        )
    if cloud_state == "paired_waiting":
        return (
            "This machine is connected to Guard Cloud. Local Guard will finish the first shared proof "
            "automatically while the daemon is running."
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
        f"{dashboard_url}/protect",
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
        "connected": "This machine is connected to Guard Cloud. Local Guard is sending the first shared proof now.",
    }
    return details.get(headline_state, "This machine is protected locally.")


_BULK_SECRET_TEXT_HINTS = (
    "credential",
    "secret",
    ".env",
    "token",
    "api key",
    "apikey",
    "password",
    "private key",
    "ssh key",
    "aws_access_key",
    "github_token",
)


def _bulk_queue_category_text(request: Mapping[str, object]) -> str:
    envelope = request.get("action_envelope_json")
    envelope_fields: list[str] = []
    if isinstance(envelope, dict):
        for key in (
            "action_type",
            "command",
            "tool_name",
            "prompt_excerpt",
            "mcp_server",
            "mcp_tool",
            "package_manager",
            "package_name",
            "script_name",
        ):
            value = envelope.get(key)
            if isinstance(value, str) and value:
                envelope_fields.append(value)
        target_paths = envelope.get("target_paths")
        if isinstance(target_paths, list):
            envelope_fields.extend(str(path) for path in target_paths if isinstance(path, str))
        decision_signals = envelope.get("signals")
        if isinstance(decision_signals, list):
            for signal in decision_signals:
                if isinstance(signal, dict):
                    for key in ("category", "title", "plain_reason"):
                        value = signal.get(key)
                        if isinstance(value, str) and value:
                            envelope_fields.append(value)
    return " ".join(
        [
            str(request.get("artifact_name") or ""),
            str(request.get("artifact_type") or ""),
            str(request.get("risk_headline") or ""),
            str(request.get("risk_summary") or ""),
            str(request.get("trigger_summary") or ""),
            str(request.get("launch_summary") or ""),
            str(request.get("why_now") or ""),
            str(request.get("launch_target") or ""),
            *_string_list(request.get("risk_signals")),
            *envelope_fields,
        ]
    )


def _bulk_decision_v2_categories(request: Mapping[str, object]) -> tuple[str, ...]:
    decision_v2 = request.get("decision_v2_json")
    if not isinstance(decision_v2, dict):
        return ()
    signals = decision_v2.get("signals")
    if not isinstance(signals, list):
        return ()
    categories: list[str] = []
    for signal in signals:
        if isinstance(signal, dict):
            category = signal.get("category")
            if isinstance(category, str) and category:
                categories.append(category)
    return tuple(categories)


def _bulk_has_secret_signal(request: Mapping[str, object]) -> bool:
    categories = _bulk_decision_v2_categories(request)
    if "secret" in categories:
        return True
    lowered = _bulk_queue_category_text(request).lower()
    return any(hint in lowered for hint in _BULK_SECRET_TEXT_HINTS)


def _bulk_read_command(command: str) -> bool:
    import re

    return re.search(r"\b(?:cat|grep|rg|sed\s+-n|awk|less|more|head|tail)\b", command.lower()) is not None


def _bulk_has_secret_path_text(text: str) -> bool:
    lowered = text.lower()
    return any(
        hint in lowered for hint in (".env", "token", "secret", "credential", "password", "private key", "api key")
    )


def _bulk_is_file_read_request(request: Mapping[str, object]) -> bool:
    envelope = request.get("action_envelope_json")
    artifact_type = str(request.get("artifact_type") or "")
    if isinstance(envelope, dict) and envelope.get("action_type") == "file_read":
        return True
    if artifact_type == "file_read_request":
        return True
    command = ""
    if isinstance(envelope, dict):
        command = str(envelope.get("command") or "")
    command = command or str(request.get("launch_target") or "")
    return _bulk_read_command(command) and _bulk_has_secret_path_text(_bulk_queue_category_text(request))


def _bulk_target_paths_are_secret(request: Mapping[str, object]) -> bool:
    from .runtime.secret_sensitivity import classify_secret_path

    envelope = request.get("action_envelope_json")
    if not isinstance(envelope, dict):
        return False
    target_paths = envelope.get("target_paths")
    if not isinstance(target_paths, list):
        return False
    workspace = envelope.get("workspace")
    workspace_dir = Path(str(workspace)).expanduser() if isinstance(workspace, str) and workspace else None
    path_context = {"cwd": workspace_dir}
    return any(
        isinstance(path, str) and classify_secret_path(path, **path_context) is not None for path in target_paths
    )


def _is_sensitive_file_read_request(request: Mapping[str, object]) -> bool:
    if not _bulk_is_file_read_request(request):
        return False
    if _bulk_target_paths_are_secret(request):
        return True
    return _bulk_has_secret_signal(request)


# Decision signal categories that must never be bulk-approved. These are the
# genuinely catastrophic or trust-breaking cases: secret exfiltration, credential
# output, prompt injection, system prompt access, guard bypass, and encoded
# payloads. Everything else is bulk-eligible with a tiered risk disclosure.
_BULK_BLOCKED_DECISION_CATEGORIES = frozenset(
    {
        "secret",
        "credential",
        "bypass",
        "prompt_injection",
        "system_prompt",
        "encoded",
    }
)

_BULK_BLOCKED_COMMAND_HINTS = (
    "prompt injection",
    "ignore previous",
    "disregard previous",
    "override instruction",
    "bypass guard",
    "disable guard",
    "skip approval",
    "ignore approval",
    "without approval",
    "guard_bypass",
    "no guard",
    "base64",
    "openssl enc",
    "xxd -r",
    "decode-and-exec",
    "exfiltrat",
    "clipboard",
    "pastebin",
)


def _bulk_request_is_bulk_blocked(request: Mapping[str, object]) -> bool:
    """True for actions that must be reviewed individually, never bulk-approved."""
    if str(request.get("policy_action") or "") == "block":
        return True
    if str(request.get("status") or "") != "pending":
        return True
    # Secret file reads and credential-bearing file reads stay gated.
    if _bulk_is_file_read_request(request) and _is_sensitive_file_read_request(request):
        return True
    categories = _bulk_decision_v2_categories(request)
    if any(category in _BULK_BLOCKED_DECISION_CATEGORIES for category in categories):
        return True
    text = _bulk_queue_category_text(request).lower()
    return any(hint in text for hint in _BULK_BLOCKED_COMMAND_HINTS)


def is_bulk_allow_once_eligible(request: Mapping[str, object]) -> bool:
    """Whether a request can be approved once via the bulk approval flow.

    Broadened beyond read-only file reads: any pending, non-blocked action that
    is not in the bulk-blocked set (secrets, exfiltration, prompt injection,
    guard bypass, destructive deletes, encoded payloads) is eligible. The
    dashboard layers a tiered risk disclosure on top of this.
    """
    return not _bulk_request_is_bulk_blocked(request)


def bulk_allow_read_only_once(
    *,
    store: GuardStore,
    request_ids: Sequence[str],
    approval_gate_input: ApprovalGateInput | None,
    now: str | None = None,
) -> dict[str, object]:
    from .approval_gate import public_config

    resolved_at = now or _now()
    gate = public_config(store.guard_home, now=resolved_at)
    if not gate.enabled or not gate.configured:
        raise ValueError("bulk_approve_gate_required")

    if len(request_ids) == 0:
        return {
            "resolved_count": 0,
            "failed": [],
            "resolution_summary": "0 actions approved once.",
        }

    bulk_resolution_action = "allow"
    bulk_resolution_scope = "artifact"
    resolved_count = 0
    failed: list[dict[str, str]] = []
    bulk_gate_grant = require_approval_decision(
        store.guard_home,
        action=bulk_resolution_action,
        scope=bulk_resolution_scope,
        approval_gate_input=approval_gate_input,
        now=resolved_at,
    )

    for request_id in request_ids:
        if not isinstance(request_id, str) or not request_id.strip():
            failed.append({"request_id": str(request_id), "error": "invalid_request_id"})
            continue
        normalized_id = request_id.strip()
        request = store.get_approval_request(normalized_id)
        if request is None or not is_bulk_allow_once_eligible(request):
            failed.append({"request_id": normalized_id, "error": "ineligible"})
            continue
        try:
            apply_approval_resolution(
                store=store,
                request_id=normalized_id,
                action=bulk_resolution_action,
                scope=bulk_resolution_scope,
                workspace=None,
                reason="bulk approve once",
                now=resolved_at,
                return_queue_result=False,
                resolve_scope_matches=True,
                approval_gate_grant=bulk_gate_grant,
                persist_policy=False,
            )
            resolved_count += 1
        except (ApprovalRequestNotFoundError, ApprovalRequestAlreadyResolvedError, ValueError) as error:
            failed.append({"request_id": normalized_id, "error": str(error)})

    return {
        "resolved_count": resolved_count,
        "failed": failed,
        "resolution_summary": f"{resolved_count} action{'s' if resolved_count != 1 else ''} approved once.",
    }


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
