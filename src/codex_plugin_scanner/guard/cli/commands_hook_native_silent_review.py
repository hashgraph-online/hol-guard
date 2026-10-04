"""Record a native review denial without opening an approval prompt."""

from __future__ import annotations

import argparse

from ..approvals import record_unprompted_review
from ..blocked_request_mode import safe_alternative_reason
from ..config import GuardConfig
from ..store import GuardStore
from .commands_hook_native_state import NativeArtifactHookState, set_native_artifact_hook_final_action
from .commands_support_hook_payload import _action_envelope_json
from .commands_support_runtime_policy import _terminalize_runtime_action_copy
from .commands_support_runtime_resolution import _runtime_detection, _runtime_request_summary


def apply_unprompted_native_review(
    state: NativeArtifactHookState,
    args: argparse.Namespace,
    store: GuardStore,
    config: GuardConfig,
    policy_action: str,
) -> None:
    """Block the harness and keep a review-tier denial in the inbox."""

    risk_summary = state.risk_summary
    if policy_action in {"review", "require-reapproval"}:
        package_evaluation = state.package_evaluation
        package_evaluation_to_dict = getattr(package_evaluation, "to_dict", None)
        record_unprompted_review(
            detection=_runtime_detection(args.harness, state.runtime_artifact),
            evaluation={
                "artifacts": [
                    {
                        "artifact_id": state.artifact_id,
                        "artifact_name": state.artifact_name,
                        "artifact_hash": state.runtime_artifact_hash,
                        "policy_action": policy_action,
                        "changed_fields": list(state.changed_capabilities),
                        "artifact_type": state.runtime_artifact.artifact_type,
                        "source_scope": state.runtime_artifact.source_scope,
                        "config_path": state.runtime_artifact.config_path,
                        "launch_target": _runtime_request_summary(state.runtime_artifact),
                        "risk_summary": risk_summary,
                        "action_envelope_json": _action_envelope_json(state.action_envelope),
                        "decision_v2_json": state.decision_v2_payload,
                        "scanner_evidence": list(state.scanner_evidence_payload),
                        "supply_chain_evaluation": (
                            package_evaluation_to_dict() if callable(package_evaluation_to_dict) else None
                        ),
                    }
                ]
            },
            store=store,
            redaction_level=config.receipt_redaction_level,
        )
    set_native_artifact_hook_final_action(state, "block")
    state.approval_prompted = False
    guidance = safe_alternative_reason(f"HOL Guard blocked this action. {risk_summary}")
    _terminalize_runtime_action_copy(state.response_payload)
    state.response_payload.update(
        terminal_action="block",
        approval_requests=[],
        prompted=False,
        operation_status="blocked",
        terminal=True,
        review_hint=guidance,
        blocked_request_guidance=guidance,
    )
    decision_copy = state.response_payload.get("decision_v2_json")
    if isinstance(decision_copy, dict):
        decision_copy["harness_message"] = guidance
    evaluation = state.response_payload.get("supply_chain_evaluation")
    if isinstance(evaluation, dict) and isinstance(evaluation.get("user_copy"), dict):
        evaluation["user_copy"].update(harness_message=guidance, next_step=guidance, dashboard_url=None)
