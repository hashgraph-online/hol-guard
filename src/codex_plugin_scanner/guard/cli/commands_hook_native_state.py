"""Guard CLI runtime artifact hook state."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations


from .commands_support import *

from ._commands_shared import *

from dataclasses import dataclass, field, replace
from typing import Any

from ..action_lattice import normalize_guard_action
from ..incident import build_incident_context
from ..models import GuardReceipt
from ..native_hook_artifact_finalize import native_artifact_finalize
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
class NativeArtifactHookState:
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
    browser_approval_wait_bound: bool | None = None
    guard_home: Path | None = None
    hook_payload: dict[str, object] = field(default_factory=dict)
    native_edge_result: Mapping[str, object] | None = None
    native_edge_receipt: Mapping[str, object] | None = None
    native_recording_only: bool = False
    receipt_recorded: bool = False
    workflow_authorization_claimed: bool = False
    approval_prompted: bool | None = None


def plan_native_artifact_hook_final_action(
    state: NativeArtifactHookState,
    policy_action: str,
    *,
    approval_request_id: str | None = None,
    approval_source: str | None = None,
    guard_home: Path | None = None,
    observed_policy_action: str | None = None,
    queued_request_id: str | None = None,
) -> Mapping[str, Any]:
    """Ask the resident what a post-review action settles to, and change nothing.

    The answer is fetched before anything is persisted: a resident that cannot
    give one raises, and the hook answers with its outage response instead of
    recording a verdict the harness never received.
    """

    raw_supply_chain = state.response_payload.get("supply_chain_evaluation")
    package_action = (
        raw_supply_chain.get("policy_action", raw_supply_chain.get("decision"))
        if isinstance(raw_supply_chain, dict)
        else None
    )
    cloud_reason_code = state.decision_v2_payload.get("package_review_cloud_reason_code")
    return native_artifact_finalize(
        {
            "previous_action": state.policy_action,
            "policy_action": policy_action,
            "observed_policy_action": observed_policy_action,
            "approval_source": approval_source,
            "approval_request_id": approval_request_id,
            "queued_request_id": queued_request_id,
            "initial_policy_action": state.initial_policy_action,
            "receipt_approval_source": state.receipt.approval_source,
            "receipt_approval_request_id": state.receipt.approval_request_id,
            "receipt_user_override": state.receipt.user_override,
            "package_review_cloud_reason_code": (
                cloud_reason_code if isinstance(cloud_reason_code, str) else None
            ),
            "supply_chain_present": isinstance(raw_supply_chain, dict),
            "supply_chain_action": package_action if isinstance(package_action, str) else None,
        },
        guard_home=guard_home if guard_home is not None else state.guard_home,
    )


def apply_native_artifact_hook_final_action(state: NativeArtifactHookState, plan: Mapping[str, Any]) -> None:
    """Write the resident's settled answer onto every hook surface.

    Rendering only: the action, the decision record, the evidence and the
    receipt fields are the plan's.
    """

    action = plan["action"]
    observed = plan["observed_action"]
    response = state.response_payload
    state.policy_action = action
    response["policy_action"] = action
    response["resolved_policy_action"] = action
    if observed is not None:
        response["observed_policy_action"] = observed
    if plan["drop_terminal_action"]:
        # Observe mode records the non-executed policy only in explicitly
        # diagnostic fields; no unqualified terminal action may contradict
        # the final action that was actually executed.
        response.pop("terminal_action", None)
    if state.action_envelope is not None:
        state.action_envelope = state.action_envelope.with_pre_execution_result(action)

    decision_v2_payload = build_decision_v2(
        action,
        reason=plan["decision_reason"],
        signals=state.decision_signals,
    ).to_dict()
    if plan["cloud_reason_code"] is not None:
        decision_v2_payload["package_review_cloud_reason_code"] = plan["cloud_reason_code"]
    state.decision_v2_payload = decision_v2_payload
    response["decision_v2_json"] = decision_v2_payload

    if plan["refresh_copy"]:
        final_risk_summary = str(decision_v2_payload["dashboard_primary_detail"])
        state.risk_summary = final_risk_summary
        response["risk_summary"] = final_risk_summary
        raw_supply_chain = response.get("supply_chain_evaluation")
        if isinstance(raw_supply_chain, dict):
            observed_supply_chain = dict(raw_supply_chain)
            raw_user_copy = raw_supply_chain.get("user_copy")
            user_copy = dict(raw_user_copy) if isinstance(raw_user_copy, dict) else {}
            if plan["observed_supply_chain_action"] is not None:
                raw_supply_chain["observed_policy_action"] = plan["observed_supply_chain_action"]
                raw_supply_chain["observed_risk_summary"] = observed_supply_chain.get("risk_summary")
                raw_supply_chain["observed_user_copy"] = observed_supply_chain.get("user_copy")
            user_copy.update(
                {
                    "title": decision_v2_payload["user_title"],
                    "summary": decision_v2_payload["user_body"],
                    "next_step": decision_v2_payload["retry_instruction"]
                    or decision_v2_payload["user_body"],
                    "harness_message": decision_v2_payload["harness_message"],
                }
            )
            raw_supply_chain.update(
                {
                    "decision": decision_v2_payload["action"],
                    "policy_action": action,
                    "risk_summary": final_risk_summary,
                    "user_copy": user_copy,
                }
            )

    incident = build_incident_context(
        harness=state.receipt.harness,
        artifact=state.runtime_artifact,
        artifact_id=state.artifact_id,
        artifact_name=state.artifact_name,
        artifact_type=state.runtime_artifact.artifact_type,
        source_scope=state.runtime_artifact.source_scope,
        config_path=state.runtime_artifact.config_path,
        changed_fields=state.changed_capabilities,
        policy_action=action,
        launch_target=None,
        risk_summary=state.risk_summary,
        guard_home=state.guard_home,
    )
    for key in ("trigger_summary", "why_now", "risk_headline"):
        response[key] = incident[key]

    patch = plan["evidence_patch"]
    policy_composition = response.get("policy_composition")
    if isinstance(policy_composition, dict):
        policy_composition.update(patch["fields"])
    for evidence in state.scanner_evidence_payload:
        if evidence.get("source") == patch["source"]:
            evidence.update(patch["fields"])

    receipt_plan = plan["receipt"]
    state.receipt = replace(
        state.receipt,
        policy_decision=receipt_plan["policy_decision"],
        approval_source=receipt_plan["approval_source"],
        approval_request_id=receipt_plan["approval_request_id"],
        user_override=receipt_plan["user_override"],
        scanner_evidence=(
            *(
                {**evidence, **patch["fields"]} if evidence.get("source") == patch["source"] else evidence
                for evidence in state.receipt.scanner_evidence
            ),
            *(dict(entry) for entry in receipt_plan["appended_evidence"]),
        ),
    )


def set_native_artifact_hook_final_action(
    state: NativeArtifactHookState,
    policy_action: str,
    *,
    approval_request_id: str | None = None,
    approval_source: str | None = None,
    guard_home: Path | None = None,
    observed_policy_action: str | None = None,
    queued_request_id: str | None = None,
) -> None:
    """Make one post-review action authoritative across every hook surface.

    For a settle with nothing persisted between the question and its answer;
    a path that records something first plans before it and applies after.
    """

    apply_native_artifact_hook_final_action(
        state,
        plan_native_artifact_hook_final_action(
            state,
            policy_action,
            approval_request_id=approval_request_id,
            approval_source=approval_source,
            guard_home=guard_home,
            observed_policy_action=observed_policy_action,
            queued_request_id=queued_request_id,
        ),
    )


def record_native_artifact_hook_receipt(
    state: NativeArtifactHookState,
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


def _record_runtime_command_activity(state: NativeArtifactHookState, store: GuardStore) -> None:
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
        prompted=(
            state.approval_prompted
            if state.approval_prompted is not None
            else command_activity_was_prompted(
                normalize_guard_action(state.initial_policy_action),
                approval_reuse_status,
            )
        ),
        approval_reuse_status=approval_reuse_status,
        workflow_authorization_claimed=state.workflow_authorization_claimed,
    )

__all__ = [
    "NativeArtifactHookState",
    "apply_native_artifact_hook_final_action",
    "plan_native_artifact_hook_final_action",
    "record_native_artifact_hook_receipt",
    "set_native_artifact_hook_final_action",
]
