"""Builders for Guard Cloud v1 events emitted by the local edge runtime."""

from __future__ import annotations

import hashlib
from typing import cast

from .models import GuardReceipt
from .schemas.guard_event_v1 import GuardEventType, GuardEventV1


def build_receipt_event(
    receipt: GuardReceipt,
    *,
    device_id: str | None = None,
    workspace_id: str | None = None,
) -> GuardEventV1:
    payload: dict[str, object] = {
        "receiptId": receipt.receipt_id,
        "harness": receipt.harness,
        "artifactId": receipt.artifact_id,
        "artifactHash": receipt.artifact_hash,
        "artifactName": receipt.artifact_name,
        "sourceScope": receipt.source_scope,
        "policyDecision": receipt.policy_decision,
        "capabilitiesSummary": receipt.capabilities_summary,
        "changedCapabilities": list(receipt.changed_capabilities),
        "provenanceSummary": receipt.provenance_summary,
        "userOverride": receipt.user_override,
    }
    event_id = f"guard-event-{_fingerprint('receipt.created', receipt.receipt_id)[:32]}"
    return GuardEventV1(
        event_id=event_id,
        idempotency_key=f"receipt.created:{receipt.receipt_id}",
        event_type="receipt.created",
        source="edge",
        occurred_at=receipt.timestamp,
        workspace_id=workspace_id,
        device_id=device_id,
        payload=payload,
    )


def build_approval_event(
    *,
    request_id: str,
    event_type: str,
    occurred_at: str,
    payload: dict[str, object],
    device_id: str | None = None,
    workspace_id: str | None = None,
) -> GuardEventV1:
    if event_type not in {"approval.created", "approval.resolved"}:
        raise ValueError("Approval event type must be approval.created or approval.resolved")
    return GuardEventV1(
        event_id=f"guard-event-{_fingerprint(event_type, request_id, occurred_at)[:32]}",
        idempotency_key=f"{event_type}:{request_id}:{occurred_at}",
        event_type=cast(GuardEventType, event_type),
        source="approval-center",
        occurred_at=occurred_at,
        workspace_id=workspace_id,
        device_id=device_id,
        payload=payload,
    )


def build_policy_event(
    *,
    policy_key: str,
    occurred_at: str,
    payload: dict[str, object],
    device_id: str | None = None,
    workspace_id: str | None = None,
) -> GuardEventV1:
    return GuardEventV1(
        event_id=f"guard-event-{_fingerprint('policy.changed', policy_key, occurred_at)[:32]}",
        idempotency_key=f"policy.changed:{policy_key}:{occurred_at}",
        event_type="policy.changed",
        source="policy",
        occurred_at=occurred_at,
        workspace_id=workspace_id,
        device_id=device_id,
        payload=payload,
    )


def build_runtime_session_event(
    *,
    session_id: str,
    occurred_at: str,
    payload: dict[str, object],
    device_id: str | None = None,
    workspace_id: str | None = None,
) -> GuardEventV1:
    return _build_edge_event(
        event_type="runtime.session",
        subject_id=session_id,
        occurred_at=occurred_at,
        payload=payload,
        device_id=device_id,
        workspace_id=workspace_id,
    )


def build_access_graph_snapshot_event(
    *,
    snapshot_id: str,
    occurred_at: str,
    payload: dict[str, object],
    device_id: str | None = None,
    workspace_id: str | None = None,
) -> GuardEventV1:
    return _build_edge_event(
        event_type="access_graph.snapshot",
        subject_id=snapshot_id,
        occurred_at=occurred_at,
        payload=payload,
        device_id=device_id,
        workspace_id=workspace_id,
    )


def build_agent_handshake_event(
    *,
    handshake_id: str,
    occurred_at: str,
    payload: dict[str, object],
    device_id: str | None = None,
    workspace_id: str | None = None,
) -> GuardEventV1:
    return _build_edge_event(
        event_type="agent.handshake",
        subject_id=handshake_id,
        occurred_at=occurred_at,
        payload=payload,
        device_id=device_id,
        workspace_id=workspace_id,
    )


def build_notification_delivery_event(
    *,
    delivery_id: str,
    occurred_at: str,
    payload: dict[str, object],
    device_id: str | None = None,
    workspace_id: str | None = None,
) -> GuardEventV1:
    return _build_edge_event(
        event_type="notification.delivery",
        subject_id=delivery_id,
        occurred_at=occurred_at,
        payload=payload,
        device_id=device_id,
        workspace_id=workspace_id,
    )


def build_harness_usage_event(
    *,
    event_type: GuardEventType,
    subject_id: str,
    occurred_at: str,
    payload: dict[str, object],
    device_id: str | None = None,
    workspace_id: str | None = None,
) -> GuardEventV1:
    if event_type not in {"harness.mcp.used", "harness.skill.activated"}:
        raise ValueError("Harness usage event type must be harness.mcp.used or harness.skill.activated")
    return _build_edge_event(
        event_type=event_type,
        subject_id=subject_id,
        occurred_at=occurred_at,
        payload=payload,
        device_id=device_id,
        workspace_id=workspace_id,
    )


def _build_edge_event(
    *,
    event_type: GuardEventType,
    subject_id: str,
    occurred_at: str,
    payload: dict[str, object],
    device_id: str | None,
    workspace_id: str | None,
) -> GuardEventV1:
    return GuardEventV1(
        event_id=f"guard-event-{_fingerprint(event_type, subject_id, occurred_at)[:32]}",
        idempotency_key=f"{event_type}:{subject_id}:{occurred_at}",
        event_type=event_type,
        source="edge",
        occurred_at=occurred_at,
        workspace_id=workspace_id,
        device_id=device_id,
        payload=payload,
    )


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256(":".join(parts).encode()).hexdigest()
