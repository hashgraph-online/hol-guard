"""Guard CLI runtime artifact hook state."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

from ._commands_shared import *

from dataclasses import dataclass, field, replace

from ..action_lattice import normalize_guard_action
from ..models import GuardReceipt
from ..runtime.command_activity_contract import ActivityApprovalReuseStatus
from ..runtime.signals import RiskSignalV2
from .commands_support_command_activity import (
    command_activity_was_prompted,
    hook_is_post_event,
    hook_is_pre_event,
    hook_post_succeeded,
    record_post_hook_command_activity_best_effort,
    record_pre_hook_command_activity_best_effort,
)


@dataclass
class RuntimeArtifactHookState:
    action_envelope: GuardActionEnvelope | None
    artifact_id: str
    artifact_name: str
    browser_approval_daemon_client: object | None
    changed_capabilities: list[str]
    decision_signals: tuple[RiskSignalV2, ...]
    decision_v2_payload: dict[str, object]
    event_name: str
    initial_policy_action: str
    package_evaluation: object | None
    policy_action: str
    receipt: GuardReceipt
    requested_policy_action: str | None
    response_payload: dict[str, object]
    risk_summary: str
    runtime_artifact: GuardArtifact
    runtime_artifact_hash: str
    scanner_evidence_payload: list[dict[str, object]]
    stored_policy_action: str | None
    guard_home: Path | None = None
    hook_payload: dict[str, object] = field(default_factory=dict)
    receipt_recorded: bool = False


def set_runtime_artifact_hook_final_action(
    state: RuntimeArtifactHookState,
    policy_action: str,
    *,
    approval_request_id: str | None = None,
    approval_source: str | None = None,
) -> None:
    """Make one post-review action authoritative across every hook surface."""

    normalized_action = normalize_guard_action(policy_action, unknown_action="block")
    state.policy_action = normalized_action
    state.response_payload["policy_action"] = normalized_action
    state.response_payload["resolved_policy_action"] = normalized_action
    if state.action_envelope is not None:
        state.action_envelope = state.action_envelope.with_pre_execution_result(normalized_action)

    decision_v2_payload = build_decision_v2(
        normalized_action,
        reason=(
            "browser-approval"
            if approval_source == "browser"
            else normalized_action
        ),
        signals=state.decision_signals,
    ).to_dict()
    state.decision_v2_payload = decision_v2_payload
    state.response_payload["decision_v2_json"] = decision_v2_payload

    policy_composition = state.response_payload.get("policy_composition")
    if isinstance(policy_composition, dict):
        policy_composition["authoritative_action"] = normalized_action
    for evidence in state.scanner_evidence_payload:
        if evidence.get("source") == "policy_composition":
            evidence["authoritative_action"] = normalized_action

    receipt_evidence = tuple(
        {
            **evidence,
            "authoritative_action": normalized_action,
        }
        if evidence.get("source") == "policy_composition"
        else evidence
        for evidence in state.receipt.scanner_evidence
    )
    if approval_source == "browser":
        receipt_evidence = (
            *receipt_evidence,
            {
                "source": "browser_approval_resolution",
                "initial_action": state.initial_policy_action,
                "authoritative_action": normalized_action,
                "approval_request_id": approval_request_id,
            },
        )
    state.receipt = replace(
        state.receipt,
        policy_decision=normalized_action,
        approval_source=approval_source or state.receipt.approval_source,
        approval_request_id=approval_request_id or state.receipt.approval_request_id,
        user_override=(
            "browser-approval"
            if approval_source == "browser"
            else state.receipt.user_override
        ),
        scanner_evidence=receipt_evidence,
    )


def record_runtime_artifact_hook_receipt(
    state: RuntimeArtifactHookState,
    store: GuardStore,
) -> None:
    """Persist the final hook receipt once, after any browser resolution."""

    if state.receipt_recorded:
        return
    store.add_receipt(state.receipt, action_envelope=state.action_envelope)
    state.receipt_recorded = True
    state.response_payload["recorded"] = True
    state.response_payload["receipt_id"] = state.receipt.receipt_id
    _record_runtime_command_activity(state, store)


def _record_runtime_command_activity(state: RuntimeArtifactHookState, store: GuardStore) -> None:
    if state.guard_home is None:
        return
    if hook_is_post_event(state.event_name):
        record_post_hook_command_activity_best_effort(
            store=store,
            guard_home=state.guard_home,
            harness=state.runtime_artifact.harness,
            event=state.event_name,
            payload=state.hook_payload,
            succeeded=hook_post_succeeded(state.event_name, state.hook_payload),
        )
        return
    if not hook_is_pre_event(state.event_name):
        return
    approval_reuse_status = ActivityApprovalReuseStatus.NOT_APPLICABLE
    approval_reuse = state.response_payload.get("approval_reuse")
    if isinstance(approval_reuse, dict):
        status = approval_reuse.get("status")
        if status in {item.value for item in ActivityApprovalReuseStatus}:
            approval_reuse_status = ActivityApprovalReuseStatus(status)
    record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=state.guard_home,
        harness=state.runtime_artifact.harness,
        event=state.event_name,
        payload=state.hook_payload,
        policy_action=state.receipt.policy_decision,
        receipt_id=state.receipt.receipt_id,
        prompted=command_activity_was_prompted(state.initial_policy_action, approval_reuse_status),
        approval_reuse_status=approval_reuse_status,
    )

__all__ = [
    "RuntimeArtifactHookState",
    "record_runtime_artifact_hook_receipt",
    "set_runtime_artifact_hook_final_action",
]
