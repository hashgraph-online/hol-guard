"""Guard CLI runtime artifact hook evaluation."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

from ._commands_shared import *
from .commands_parser_helpers import *

from .commands_hook_runtime_state import RuntimeArtifactHookState

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
    event_name = _hook_event_name(payload) or "PreToolUse"
    package_evaluation = None
    if runtime_artifact.artifact_type == "package_request" and runtime_workspace is not None:
        package_evaluation = evaluate_package_request_artifact(
            artifact=runtime_artifact,
            store=store,
            workspace_dir=runtime_workspace,
        )
        runtime_artifact_hash = package_request_policy_hash(
            artifact=runtime_artifact,
            store=store,
            workspace_dir=runtime_workspace,
            evaluation=package_evaluation,
        )
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
        response_payload = {
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
            payload=payload,
            policy_action="allow",
        )
        return 0
    stored_policy_action = _runtime_stored_policy_action(
        store=store,
        harness=policy_harness,
        artifact=runtime_artifact,
        artifact_id=artifact_id,
        artifact_hash=runtime_artifact_hash,
        workspace=str(runtime_workspace) if runtime_workspace else None,
    )
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
        payload.get("policy_action"),
    )
    policy_action = requested_policy_action
    if policy_action not in VALID_GUARD_ACTIONS:
        policy_action = _runtime_artifact_policy_action(config, runtime_artifact, args.harness)
    if _canonical_harness_name(args.harness) == "claude-code" and event_name in {
        "PostToolUse",
        "PostToolUseFailure",
    }:
        saved = _persist_claude_native_permission_for_runtime_artifact(
            store=store,
            payload=payload,
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
            payload=payload,
            policy_action="allow" if saved else "require-reapproval",
        )
        return 0
    if package_evaluation is not None and runtime_workspace is not None:
        package_evaluation = _apply_stored_package_policy_override(
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
    if package_evaluation is not None:
        if guard_action_severity(package_evaluation.policy_action) > guard_action_severity(policy_action):
            policy_action = package_evaluation.policy_action
    if data_flow_signals:
        data_flow_action = resolve_risk_action(
            config,
            "data_flow_exfiltration",
            harness=policy_harness,
        )
        if guard_action_severity(data_flow_action) > guard_action_severity(policy_action):
            policy_action = data_flow_action
    _pre_scanner_policy_action = policy_action
    package_controls_pre_scanner_summary = (
        package_evaluation is not None
        and guard_action_severity(package_evaluation.policy_action)
        >= guard_action_severity(_pre_scanner_policy_action)
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
    if package_controls_pre_scanner_summary:
        risk_signals = [
            str(item.get("message") or item.get("code") or "")
            for item in package_evaluation.reasons
        ]
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
        user_override=_optional_string(payload.get("user_override")),
        scanner_evidence=scanner_evidence_payload,
        approval_source=(
            "inline"
            if _optional_string(payload.get("user_override")) is not None
            else "approval_center"
            if policy_action == "require-reapproval"
            else "policy"
        ),
    )
    store.add_receipt(receipt, action_envelope=action_envelope)
    response_payload = {
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
    }
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
                payload=payload,
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
