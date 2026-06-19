"""Guard CLI runtime artifact hook evaluation."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _now
    from .commands_support_hook_payload import _coalesce_string
    from .commands_support_hook_state import _cursor_native_shell_is_approved
    from .commands_support_interaction import _emit, _record_harness_usage_for_hook
    from .commands_support_permission_store import (
        _persist_claude_native_permission_for_runtime_artifact,
        _record_cursor_pending_shell_permission,
    )
    from .commands_support_prompts import _runtime_artifact_native_reason
    from .commands_support_runtime_artifacts import _hook_event_name, _optional_string
    from .commands_support_runtime_policy import (
        _remembered_rule_rejection_reason,
        _runtime_artifact_exact_match_context,
        _runtime_artifact_policy_action,
        _runtime_data_flow_summary,
        _runtime_stored_policy_action,
    )
    from .commands_support_runtime_resolution import (
        _canonical_harness_name,
        _legacy_claude_alias_runtime_artifact,
        _queue_claude_native_approval_gate_fallback,
        _runtime_capabilities_summary,
        _runtime_request_summary,
        _runtime_requested_path,
    )


from ..models import GuardAction
from ._commands_shared import *
from .commands_hook_runtime_state import RuntimeArtifactHookState
from .commands_parser_helpers import *
from .commands_support_runtime_policy import _remembered_rule_rejection_reason, _runtime_artifact_exact_match_context


def _resolved_guard_action(value: object, fallback: GuardAction) -> GuardAction:
    if value == "allow":
        return "allow"
    if value == "warn":
        return "warn"
    if value == "review":
        return "review"
    if value == "block":
        return "block"
    if value == "sandbox-required":
        return "sandbox-required"
    if value == "require-reapproval":
        return "require-reapproval"
    return fallback


def _evaluate_runtime_artifact_hook(
    args: argparse.Namespace,
    *,
    action_envelope: GuardActionEnvelope | None,
    config: GuardConfig,
    context: HarnessContext,
    data_flow_signals: tuple[RiskSignalV2, ...],
    guard_home: Path,
    payload: Mapping[str, object],
    runtime_artifact: GuardArtifact,
    runtime_workspace: Path | None,
    store: GuardStore,
) -> int | RuntimeArtifactHookState:
    payload_map = dict(payload)
    event_name = _hook_event_name(payload_map) or "PreToolUse"
    package_evaluation = None
    if runtime_artifact.artifact_type == "package_request":
        package_evaluation = evaluate_package_request_artifact(
            artifact=runtime_artifact,
            store=store,
            workspace_dir=runtime_workspace,
        )
        if runtime_workspace is not None:
            runtime_artifact_hash = package_request_policy_hash(
                artifact=runtime_artifact,
                store=store,
                workspace_dir=runtime_workspace,
                evaluation=package_evaluation,
            )
        else:
            runtime_artifact_hash = artifact_hash(runtime_artifact)
    else:
        runtime_artifact_hash = artifact_hash(runtime_artifact)
    artifact_id = runtime_artifact.artifact_id
    artifact_name = runtime_artifact.name
    policy_harness = _canonical_harness_name(args.harness)
    if (
        policy_harness == "cursor"
        and event_name == "PreToolUse"
        and runtime_artifact.artifact_type == "tool_action_request"
        and _cursor_native_shell_is_approved(store, payload)
    ):
        response_payload: dict[str, object] = {
            "recorded": True,
            "harness": policy_harness,
            "artifact_id": artifact_id,
            "artifact_name": artifact_name,
            "artifact_type": runtime_artifact.artifact_type,
            "policy_action": "allow",
        }
        _emit("hook", response_payload, getattr(args, "json", False))
        _record_harness_usage_for_hook(
            store=store,
            action_envelope=action_envelope,
            payload=payload_map,
            policy_action="allow",
        )
        return 0
    runtime_exact_match_context = _runtime_artifact_exact_match_context(runtime_artifact)
    policy_lookup = store.resolve_policy_decision_lookup(
        policy_harness,
        artifact_id,
        artifact_hash=runtime_artifact_hash,
        workspace=str(runtime_workspace) if runtime_workspace else None,
        publisher=runtime_artifact.publisher,
        runtime_exact_match_context=runtime_exact_match_context,
    )
    stored_policy_action = _runtime_stored_policy_action(
        store=store,
        harness=policy_harness,
        artifact=runtime_artifact,
        artifact_id=artifact_id,
        artifact_hash=runtime_artifact_hash,
        workspace=str(runtime_workspace) if runtime_workspace else None,
        decision_lookup=policy_lookup,
    )
    remembered_rule_rejection = policy_lookup["ignored_local_integrity"]
    trust_status = policy_lookup["trust_status"]
    if stored_policy_action is None:
        legacy_artifact = _legacy_claude_alias_runtime_artifact(
            artifact=runtime_artifact,
            requested_harness=args.harness,
            home_dir=context.home_dir,
            workspace=runtime_workspace,
        )
        if legacy_artifact is not None:
            stored_policy_action = _runtime_stored_policy_action(
                store=store,
                harness=args.harness,
                artifact=legacy_artifact,
                artifact_id=legacy_artifact.artifact_id,
                artifact_hash=artifact_hash(legacy_artifact),
                workspace=str(runtime_workspace) if runtime_workspace else None,
            )
    requested_policy_action = _coalesce_string(
        getattr(args, "policy_action", None),
        stored_policy_action,
        payload_map.get("policy_action"),
    )
    if requested_policy_action == "allow":
        policy_action: GuardAction = "allow"
    elif requested_policy_action == "warn":
        policy_action = "warn"
    elif requested_policy_action == "review":
        policy_action = "review"
    elif requested_policy_action == "block":
        policy_action = "block"
    elif requested_policy_action == "sandbox-required":
        policy_action = "sandbox-required"
    elif requested_policy_action == "require-reapproval":
        policy_action = "require-reapproval"
    else:
        policy_action = _resolved_guard_action(
            _runtime_artifact_policy_action(config, runtime_artifact, args.harness),
            "warn",
        )
    if _canonical_harness_name(args.harness) == "claude-code" and event_name in {
        "PostToolUse",
        "PostToolUseFailure",
    }:
        saved = _persist_claude_native_permission_for_runtime_artifact(
            store=store,
            payload=payload_map,
            artifact=runtime_artifact,
            artifact_hash=runtime_artifact_hash,
            action="allow",
            reason="Approved in Claude native approval prompt.",
        )
        if saved:
            receipt = build_receipt(
                harness=policy_harness,
                artifact_id=artifact_id,
                artifact_hash=runtime_artifact_hash,
                policy_decision="allow",
                capabilities_summary=_runtime_capabilities_summary(runtime_artifact),
                changed_capabilities=[runtime_artifact.artifact_type, "claude-native-approved"],
                provenance_summary=f"runtime tool request approved from {runtime_artifact.config_path}",
                artifact_name=artifact_name,
                source_scope=runtime_artifact.source_scope,
                user_override="claude-native-approve",
                approval_source="inline",
            )
            store.add_receipt(receipt)
        else:
            _queue_claude_native_approval_gate_fallback(
                store=store,
                harness=policy_harness,
                artifact=runtime_artifact,
                artifact_digest=runtime_artifact_hash,
                approval_center_url=load_guard_daemon_url(guard_home) or "http://127.0.0.1:5474",
                action_envelope=action_envelope,
            )
        _record_harness_usage_for_hook(
            store=store,
            action_envelope=action_envelope,
            payload=payload_map,
            policy_action="allow" if saved else "require-reapproval",
        )
        return 0
    if package_evaluation is not None and runtime_workspace is not None:
        package_evaluation = apply_stored_package_policy_override(
            package_evaluation,
            store=store,
            artifact=runtime_artifact,
            artifact_hash=runtime_artifact_hash,
            workspace_dir=runtime_workspace,
            now=_now(),
        )
    changed_capabilities = [runtime_artifact.artifact_type]
    scanner_evidence = (
        scan_action_for_cisco_evidence(action_envelope, workspace=runtime_workspace)
        if action_envelope is not None
        else ()
    )
    scanner_evidence_payload = [signal.to_dict() for signal in scanner_evidence]
    package_policy_action: GuardAction | None = (
        _resolved_guard_action(package_evaluation.policy_action, "warn") if package_evaluation is not None else None
    )
    if package_policy_action is not None and guard_action_severity(package_policy_action) > guard_action_severity(
        policy_action
    ):
        policy_action = package_policy_action
    if data_flow_signals:
        data_flow_action = _resolved_guard_action(
            resolve_risk_action(
                config,
                "data_flow_exfiltration",
                harness=policy_harness,
            ),
            policy_action,
        )
        if guard_action_severity(data_flow_action) > guard_action_severity(policy_action):
            policy_action = data_flow_action
    _pre_scanner_policy_action = policy_action
    package_controls_pre_scanner_summary = (
        package_evaluation is not None
        and package_policy_action is not None
        and guard_action_severity(package_policy_action) >= guard_action_severity(_pre_scanner_policy_action)
    )
    if scanner_evidence and requested_policy_action not in VALID_GUARD_ACTIONS:
        scanner_action = policy_action_for_cisco_signals(
            scanner_evidence,
            config=config,
            harness=policy_harness,
        )
        if guard_action_severity(scanner_action) > guard_action_severity(policy_action):
            policy_action = scanner_action
    scanner_raised_to_block = (
        policy_action == "block" and _pre_scanner_policy_action != "block" and bool(scanner_evidence)
    )
    base_decision_signals = data_flow_signals or artifact_risk_signals_v2(runtime_artifact)
    scanner_decision_signals = tuple(cisco_risk_signal_v3_to_v2(signal) for signal in scanner_evidence)
    if scanner_raised_to_block and scanner_decision_signals:
        decision_signals = (*scanner_decision_signals, *base_decision_signals)
    else:
        decision_signals = (*base_decision_signals, *scanner_decision_signals)
    scanner_risk_signals = [signal.plain_language_summary for signal in scanner_evidence]
    if data_flow_signals:
        risk_signals = [signal.plain_reason for signal in data_flow_signals]
        risk_summary = _runtime_data_flow_summary(data_flow_signals)
    else:
        risk_signals = list(artifact_risk_signals(runtime_artifact))
        risk_summary = artifact_risk_summary(runtime_artifact)
    if package_controls_pre_scanner_summary and package_evaluation is not None:
        risk_signals = [str(item.get("message") or item.get("code") or "") for item in package_evaluation.reasons]
        risk_summary = package_evaluation.risk_summary
        scanner_evidence_payload.extend(
            {
                "decision": package_evaluation.decision,
                "enforcement": package_evaluation.enforcement,
                "exception_id": package_evaluation.exception_id,
                "matched_rule_id": package_evaluation.matched_rule_id,
                "package": package,
            }
            for package in package_evaluation.packages
        )
    if scanner_risk_signals:
        risk_signals.extend(scanner_risk_signals)
        if scanner_raised_to_block:
            risk_summary = scanner_risk_signals[0]
    if action_envelope is not None:
        action_envelope = action_envelope.with_pre_execution_result(policy_action)
    decision_v2 = build_decision_v2(policy_action, reason=policy_action, signals=decision_signals)
    decision_v2_payload = decision_v2.to_dict()
    if package_evaluation is not None and package_evaluation.policy_action == policy_action:
        decision_v2_payload["user_title"] = package_evaluation.user_copy.title
        decision_v2_payload["user_body"] = package_evaluation.user_copy.summary
        decision_v2_payload["harness_message"] = package_evaluation.user_copy.harness_message
        decision_v2_payload["dashboard_primary_detail"] = package_evaluation.user_copy.summary
    incident = build_incident_context(
        harness=args.harness,
        artifact=runtime_artifact,
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        artifact_type=runtime_artifact.artifact_type,
        source_scope=runtime_artifact.source_scope,
        config_path=runtime_artifact.config_path,
        changed_fields=changed_capabilities,
        policy_action=policy_action,  # type: ignore[arg-type]
        launch_target=_runtime_request_summary(runtime_artifact),
        risk_summary=risk_summary,
    )
    receipt = build_receipt(
        harness=args.harness,
        artifact_id=artifact_id,
        artifact_hash=runtime_artifact_hash,
        policy_decision=policy_action,
        capabilities_summary=_runtime_capabilities_summary(runtime_artifact),
        changed_capabilities=changed_capabilities,
        provenance_summary=f"runtime tool request evaluated from {runtime_artifact.config_path}",
        artifact_name=artifact_name,
        source_scope=runtime_artifact.source_scope,
        user_override=_optional_string(payload_map.get("user_override")),
        scanner_evidence=scanner_evidence_payload,
        approval_source=(
            "inline"
            if _optional_string(payload_map.get("user_override")) is not None
            else "approval_center"
            if policy_action == "require-reapproval"
            else "policy"
        ),
    )
    store.add_receipt(receipt, action_envelope=action_envelope)
    response_payload: dict[str, object] = {
        "recorded": True,
        "harness": _canonical_harness_name(args.harness),
        "artifact_id": artifact_id,
        "artifact_name": artifact_name,
        "artifact_type": runtime_artifact.artifact_type,
        "policy_action": policy_action,
        "risk_signals": risk_signals,
        "risk_summary": risk_summary,
        "scanner_evidence": scanner_evidence_payload,
        "decision_v2_json": decision_v2_payload,
        "artifact_label": incident["artifact_label"],
        "source_label": incident["source_label"],
        "trigger_summary": incident["trigger_summary"],
        "why_now": incident["why_now"],
        "launch_summary": incident["launch_summary"],
        "risk_headline": incident["risk_headline"],
        "path_summary": _runtime_requested_path(runtime_artifact),
        "trust_status": trust_status,
    }
    if remembered_rule_rejection is not None:
        response_payload["remembered_rule_rejection"] = remembered_rule_rejection
        if policy_action in {"review", "require-reapproval"}:
            remembered_rule_reason = _remembered_rule_rejection_reason(
                response_payload=response_payload,
                artifact=runtime_artifact,
            )
        else:
            remembered_rule_reason = None
        if remembered_rule_reason is not None:
            decision_v2_payload["harness_message"] = remembered_rule_reason
            decision_v2_payload["dashboard_primary_detail"] = remembered_rule_reason
            response_payload["risk_headline"] = remembered_rule_reason
    if package_evaluation is not None:
        response_payload["supply_chain_evaluation"] = package_evaluation.to_dict()
    if (
        _canonical_harness_name(args.harness) == "cursor"
        and event_name == "PreToolUse"
        and runtime_artifact.artifact_type == "tool_action_request"
    ):
        from ..adapters.cursor_hooks import cursor_hook_would_prompt_user

        if cursor_hook_would_prompt_user(
            policy_action=policy_action,
            guard_payload=response_payload,
        ):
            native_reason = _runtime_artifact_native_reason(runtime_artifact, response_payload)
            _record_cursor_pending_shell_permission(
                store=store,
                guard_home=context.guard_home,
                payload=payload_map,
                reason=native_reason,
                artifact=runtime_artifact,
                artifact_hash=runtime_artifact_hash,
            )
    return RuntimeArtifactHookState(
        action_envelope=action_envelope,
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        browser_approval_daemon_client=None,
        changed_capabilities=changed_capabilities,
        decision_v2_payload=decision_v2_payload,
        event_name=event_name,
        package_evaluation=package_evaluation,
        policy_action=policy_action,
        requested_policy_action=requested_policy_action,
        response_payload=response_payload,
        risk_summary=risk_summary,
        runtime_artifact=runtime_artifact,
        runtime_artifact_hash=runtime_artifact_hash,
        scanner_evidence_payload=scanner_evidence_payload,
        stored_policy_action=stored_policy_action,
    )


__all__ = [
    "_evaluate_runtime_artifact_hook",
]
