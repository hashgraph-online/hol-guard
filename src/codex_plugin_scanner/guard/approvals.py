"""Approval queue orchestration for local Guard reviews."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from .adapters import get_adapter
from .adapters.base import HarnessContext
from .models import GuardApprovalRequest, HarnessDetection, PolicyDecision
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
        request = GuardApprovalRequest(
            request_id=request_id,
            harness=detection.harness,
            artifact_id=artifact_id,
            artifact_name=_artifact_name(item, artifact_id),
            artifact_hash=str(item.get("artifact_hash") or "unknown"),
            policy_action=str(policy_action),
            recommended_scope="publisher" if artifact is not None and artifact.publisher else "artifact",
            changed_fields=tuple(_string_list(item.get("changed_fields"))),
            source_scope=_source_scope(item, artifact),
            config_path=_config_path(item, artifact),
            review_command=f"{GUARD_COMMAND} approvals approve {request_id}",
            approval_url=f"{approval_center_url.rstrip('/')}/approvals/{request_id}",
            publisher=artifact.publisher if artifact is not None else None,
        )
        store.add_approval_request(request, timestamp)
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
        workspace=workspace if scope == "workspace" else None,
        publisher=str(request["publisher"]) if scope == "publisher" else None,
        reason=reason,
    )
    store.upsert_policy(decision, now or _now())
    store.resolve_approval_request(
        request_id,
        resolution_action=action,
        resolution_scope=scope,
        reason=reason,
        resolved_at=now or _now(),
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
    adapter = get_adapter(harness)
    flow = adapter.approval_flow()
    count = len(queued)
    return (
        f"Guard queued {count} approval request{'s' if count != 1 else ''} for {harness}. "
        f"Open {approval_center_url} to review them. "
        f"{flow['fallback_hint']}"
    )


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


def _source_scope(item: dict[str, object], artifact) -> str:
    if artifact is not None:
        return artifact.source_scope
    value = item.get("source_scope")
    if isinstance(value, str) and value:
        return value
    return "project"


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
