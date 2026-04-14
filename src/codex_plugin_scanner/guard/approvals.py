"""Approval queue orchestration for local Guard reviews."""

from __future__ import annotations

import time
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from .adapters import get_adapter
from .adapters.base import HarnessContext
from .incident import build_incident_context
from .models import GuardApprovalRequest, HarnessDetection, PolicyDecision
from .risk import artifact_risk_signals, artifact_risk_summary
from .store import GuardStore

GUARD_COMMAND = "hol-guard"


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
        risk_summary = artifact_risk_summary(artifact) if artifact is not None else None
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
            risk_signals=artifact_risk_signals(artifact) if artifact is not None else (),
            artifact_label=incident["artifact_label"],
            source_label=incident["source_label"],
            trigger_summary=incident["trigger_summary"],
            why_now=incident["why_now"],
            launch_summary=incident["launch_summary"],
            risk_headline=incident["risk_headline"],
        )
        persisted_request_id = store.add_approval_request(request, timestamp)
        if persisted_request_id != request.request_id:
            request = replace(
                request,
                request_id=persisted_request_id,
                review_command=f"{GUARD_COMMAND} approvals approve {persisted_request_id}",
                approval_url=f"{approval_center_url.rstrip('/')}/approvals/{persisted_request_id}",
            )
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
) -> dict[str, object]:
    request = store.get_approval_request(request_id)
    if request is None:
        raise ValueError(f"Unknown approval request: {request_id}")
    if request["status"] != "pending":
        raise ValueError(f"Approval request already resolved: {request_id}")
    if scope == "workspace" and not workspace:
        raise ValueError(f"Approval request {request_id} requires --workspace for workspace scope.")
    if scope == "publisher" and not isinstance(request.get("publisher"), str):
        raise ValueError(f"Approval request {request_id} has no publisher scope to approve.")
    decision = PolicyDecision(
        harness=str(request["harness"]),
        scope=scope,
        action="allow" if action == "allow" else "block",
        artifact_id=str(request["artifact_id"]) if scope == "artifact" else None,
        artifact_hash=str(request["artifact_hash"]) if scope == "artifact" else None,
        workspace=workspace if scope == "workspace" else None,
        publisher=str(request["publisher"]) if scope == "publisher" else None,
        reason=reason,
    )
    store.upsert_policy(decision, now or _now())
    resolved_at = now or _now()
    resolved_ids = store.resolve_matching_approval_requests(
        harness=str(request["harness"]),
        scope=scope,
        artifact_id=str(request["artifact_id"]) if scope == "artifact" else None,
        workspace=workspace if scope == "workspace" else None,
        publisher=(
            str(request["publisher"]) if scope == "publisher" and isinstance(request.get("publisher"), str) else None
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
    return updated


def approval_center_hint(
    *,
    context: HarnessContext,
    harness: str,
    approval_center_url: str,
    queued: list[dict[str, object]],
) -> str:
    del context
    flow = approval_prompt_flow(harness)
    count = len(queued)
    risk_summary = _queue_risk_summary(queued)
    return (
        f"Guard queued {count} approval request{'s' if count != 1 else ''} for {harness}. "
        f"{flow['summary']} "
        f"Open {approval_center_url} to review them. "
        f"{risk_summary} "
        f"{flow['fallback_hint']}"
    )


def approval_prompt_flow(harness: str) -> dict[str, object]:
    try:
        flow = get_adapter(harness).approval_flow()
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
    if artifact is not None:
        if artifact.url:
            return artifact.url
        if artifact.command:
            parts = [artifact.command, *artifact.args]
            return " ".join(parts)
    value = item.get("launch_target")
    if isinstance(value, str) and value:
        return value
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


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
