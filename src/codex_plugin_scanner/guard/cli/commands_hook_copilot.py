"""Guard CLI Copilot hook helpers."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from ..mcp_tool_calls import ToolCallDecision
    from ._commands_shared import _hook_command_text, _now
    from .commands_support_hook_payload import _action_envelope_json, _approval_surface_policy_for_flow
    from .commands_support_interaction import (
        _attach_primary_approval_link,
        _codex_browser_wait_metadata,
        _emit,
        _preferred_approval_review_url,
        _record_harness_usage_for_hook,
        _should_emit_copilot_hook_response,
    )
    from .commands_support_prompts import (
        _copilot_hook_reason,
        _emit_copilot_hook_response,
        _emit_copilot_permission_request_response,
    )
    from .commands_support_runtime_artifacts import _optional_string
    from .commands_support_runtime_policy import _localize_pending_approval_copy, _native_approval_center_context
    from .commands_support_runtime_resolution import _canonical_harness_name, _runtime_detection


from ..models import GuardAction
from ..runtime.command_activity_contract import ActivityApprovalReuseStatus
from ._commands_shared import *
from .commands_parser_helpers import *
from .commands_support_command_activity import (
    command_activity_was_prompted,
    record_pre_hook_command_activity_best_effort,
)


def _record_copilot_pre_activity(
    *,
    store: GuardStore,
    context: HarnessContext,
    event: str,
    payload: Mapping[str, object],
    policy_action: GuardAction,
    receipt_id: str,
    decision: ToolCallDecision,
    runtime_workspace: Path | None,
) -> None:
    raw_reuse_status = decision.approval_reuse_status
    reuse_status = (
        ActivityApprovalReuseStatus(raw_reuse_status)
        if raw_reuse_status in {item.value for item in ActivityApprovalReuseStatus}
        else ActivityApprovalReuseStatus.NOT_APPLICABLE
    )
    _ = record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=context.guard_home,
        harness="copilot",
        event=event,
        payload=payload,
        policy_action=policy_action,
        receipt_id=receipt_id,
        prompted=command_activity_was_prompted(decision.current_action or policy_action, reuse_status),
        approval_reuse_status=reuse_status,
        cwd=runtime_workspace,
        home_dir=context.home_dir,
    )


def _copilot_tool_decision_scanner_evidence(
    decision: ToolCallDecision,
) -> tuple[dict[str, object], ...]:
    evidence: list[dict[str, object]] = []
    if decision.normalization_reason_code is not None:
        evidence.append(
            {
                "source": "guard_action_normalizer",
                "input_source": "stored_tool_policy",
                "reason_code": decision.normalization_reason_code,
                "original_action": decision.original_action,
                "normalized_action": decision.action,
            }
        )
    if decision.approval_reuse_reason_code is not None:
        evidence.append(
            {
                "source": "approval_reuse",
                "status": decision.approval_reuse_status,
                "reason_code": decision.approval_reuse_reason_code,
                "current_action": decision.current_action,
                "saved_action": decision.saved_action,
                "effective_action": decision.action,
            }
        )
    return tuple(evidence)


def _copilot_approval_reuse_evidence(
    decision: ToolCallDecision,
) -> dict[str, object] | None:
    if decision.approval_reuse_reason_code is None:
        return None
    return {
        "status": decision.approval_reuse_status,
        "reason_code": decision.approval_reuse_reason_code,
        "current_action": decision.current_action,
        "saved_action": decision.saved_action,
        "effective_action": decision.action,
    }


def _queue_observed_copilot_approval(
    *,
    artifact: GuardArtifact,
    artifact_hash: str,
    artifact_name: str,
    args: argparse.Namespace,
    action_envelope: GuardActionEnvelope | None,
    config: GuardConfig,
    context: HarnessContext,
    decision: ToolCallDecision,
    guard_home: Path,
    managed_install: dict[str, object] | None,
    payload: Mapping[str, object],
    runtime_arguments: object,
    runtime_workspace: Path | None,
    store: GuardStore,
) -> list[dict[str, object]]:
    approval_center_url = ensure_guard_daemon(guard_home)
    runtime_detection = _runtime_detection(args.harness, artifact)
    evaluation_payload: dict[str, object] = {
        "artifacts": [
            {
                "artifact_id": artifact.artifact_id,
                "artifact_name": artifact_name,
                "artifact_hash": artifact_hash,
                "policy_action": "require-reapproval",
                "changed_fields": ["runtime_tool_call", *decision.signals],
                "artifact_type": artifact.artifact_type,
                "source_scope": artifact.source_scope,
                "config_path": artifact.config_path,
                "launch_target": json.dumps(runtime_arguments, sort_keys=True)
                if runtime_arguments is not None
                else artifact.command,
                "action_envelope_json": _action_envelope_json(action_envelope),
                "scanner_evidence": list(_copilot_tool_decision_scanner_evidence(decision)),
            }
        ]
    }
    approval_flow = get_adapter(args.harness).approval_flow(managed_install=managed_install)
    try:
        daemon_client = load_guard_surface_daemon_client(guard_home)
    except RuntimeError:
        queued = queue_blocked_approvals(
            redaction_level=config.receipt_redaction_level,
            detection=runtime_detection,
            evaluation=evaluation_payload,
            store=store,
            approval_center_url=approval_center_url,
            now=_now(),
        )
    else:
        session = daemon_client.start_session(
            harness=args.harness,
            surface="harness-adapter",
            workspace=str(runtime_workspace) if runtime_workspace else None,
            client_name=f"{args.harness}-permission-hook",
            client_title=f"{args.harness} permission hook",
            client_version="1.0.0",
            capabilities=["approval-resolution", "receipt-view"],
        )
        blocked_operation = daemon_client.queue_blocked_operation(
            session_id=str(session["session_id"]),
            operation_type="tool_call",
            harness=args.harness,
            metadata={
                "tool_name": str(payload.get("tool_name", "")),
                "hook_name": "permissionRequest",
                "hook_event_name": "PermissionRequest",
                **_codex_browser_wait_metadata(
                    args=args,
                    event_name="PermissionRequest",
                    policy_action="require-reapproval",
                    config=config,
                    payload=payload,
                ),
                "command_text": _hook_command_text(payload),
                "workspace": str(runtime_workspace) if runtime_workspace else None,
            },
            detection=runtime_detection.to_dict(),
            evaluation=evaluation_payload,
            approval_center_url=approval_center_url,
            approval_surface_policy=_approval_surface_policy_for_flow(
                config.approval_surface_policy,
                approval_flow,
            ),
            open_key=artifact.artifact_id,
            redaction_level=config.receipt_redaction_level,
        )
        queued = blocked_operation.get("approval_requests")
        if not isinstance(queued, list):
            queued = []
    return queued


def _run_hook_copilot_pretool(
    args: argparse.Namespace,
    *,
    action_envelope: GuardActionEnvelope | None,
    config: GuardConfig,
    context: HarnessContext,
    copilot_hook_stage: str | None,
    copilot_runtime_tool_call: tuple[GuardArtifact, str, object] | None,
    output_stream: TextIO | None = None,
    payload: Mapping[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
    fresh_tool_call_authority_provider: (
        Callable[[], tuple[GuardConfig, GuardArtifact, str, object] | None] | None
    ) = None,
) -> int | None:
    if copilot_runtime_tool_call is None or copilot_hook_stage != "pretooluse":
        return None
    runtime_artifact, runtime_artifact_hash, runtime_arguments = copilot_runtime_tool_call
    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=runtime_artifact,
        artifact_hash=runtime_artifact_hash,
        arguments=runtime_arguments,
        fresh_authority_provider=fresh_tool_call_authority_provider,
    )
    if decision.post_claim_authority is not None:
        config = decision.post_claim_authority.config
        runtime_artifact = decision.post_claim_authority.artifact
        runtime_artifact_hash = decision.post_claim_authority.artifact_hash
        runtime_arguments = decision.post_claim_authority.arguments
    policy_action = cast(
        GuardAction,
        {
            "allow": "allow",
            "warn": "allow",
            "review": "require-reapproval",
            "block": "block",
            "sandbox-required": "sandbox-required",
            "require-reapproval": "require-reapproval",
        }.get(decision.action, "require-reapproval"),
    )
    approval_reuse = _copilot_approval_reuse_evidence(decision)
    decision_scanner_evidence = _copilot_tool_decision_scanner_evidence(decision)
    saved_policy_blocks = decision.saved_action == "block"
    post_claim_failure = decision.post_claim_revalidated and policy_action != "allow"
    terminal_action = policy_action in {"block", "sandbox-required"}
    now = _now()
    if config.mode == "observe" and policy_action != "allow" and not saved_policy_blocks and not post_claim_failure:
        if not terminal_action:
            _queue_observed_copilot_approval(
                artifact=runtime_artifact,
                artifact_hash=runtime_artifact_hash,
                artifact_name=runtime_artifact.name,
                args=args,
                action_envelope=action_envelope,
                config=config,
                context=context,
                decision=decision,
                guard_home=context.guard_home,
                managed_install=None,
                payload=payload,
                runtime_arguments=runtime_arguments,
                runtime_workspace=runtime_workspace,
                store=store,
            )
        policy_action = "allow"
    # Copilot review/reapproval continues to PermissionRequest, which owns that
    # activity. PreToolUse records only decisions that terminate at this stage.
    if policy_action == "allow":
        receipt = allow_tool_call(
            store=store,
            artifact=runtime_artifact,
            artifact_hash=runtime_artifact_hash,
            decision_source="pre-tool-hook",
            now=now,
            signals=decision.signals,
            risk_categories=decision.risk_categories,
            remember=False,
            arguments=runtime_arguments,
            additional_scanner_evidence=decision_scanner_evidence,
        )
        if _should_emit_copilot_hook_response(args):
            _record_copilot_pre_activity(
                store=store,
                context=context,
                event="preToolUse",
                payload=payload,
                policy_action=policy_action,
                receipt_id=receipt.receipt_id,
                decision=decision,
                runtime_workspace=runtime_workspace,
            )
            _record_harness_usage_for_hook(
                store=store,
                action_envelope=action_envelope,
                payload=payload,
                policy_action=policy_action,
            )
            _emit_copilot_hook_response(
                policy_action="allow",
                reason="",
                approval_reuse=approval_reuse,
                scanner_evidence=decision_scanner_evidence,
                output_stream=output_stream,
            )
            return 0
    else:
        if policy_action in {"block", "sandbox-required"}:
            receipt = block_tool_call(
                store=store,
                artifact=runtime_artifact,
                artifact_hash=runtime_artifact_hash,
                decision_source="pre-tool-hook",
                now=now,
                signals=decision.signals,
                risk_categories=decision.risk_categories,
                arguments=runtime_arguments,
                additional_scanner_evidence=decision_scanner_evidence,
                policy_action=policy_action,
            )
            if _should_emit_copilot_hook_response(args):
                _record_copilot_pre_activity(
                    store=store,
                    context=context,
                    event="preToolUse",
                    payload=payload,
                    policy_action=policy_action,
                    receipt_id=receipt.receipt_id,
                    decision=decision,
                    runtime_workspace=runtime_workspace,
                )
        if _should_emit_copilot_hook_response(args):
            _record_harness_usage_for_hook(
                store=store,
                action_envelope=action_envelope,
                payload=payload,
                policy_action=policy_action,
            )
            _emit_copilot_hook_response(
                policy_action=policy_action,
                reason=(
                    f"HOL Guard blocked {runtime_artifact.name}. {decision.summary}"
                    if saved_policy_blocks
                    else _copilot_hook_reason(decision.summary, runtime_artifact.name)
                ),
                approval_reuse=approval_reuse,
                scanner_evidence=decision_scanner_evidence,
                output_stream=output_stream,
            )
            return 0


def _run_hook_copilot_permission_request(
    args: argparse.Namespace,
    *,
    action_envelope: GuardActionEnvelope | None,
    config: GuardConfig,
    context: HarnessContext,
    copilot_permission_request: tuple[GuardArtifact, str, object] | None,
    guard_home: Path,
    managed_install: dict[str, object] | None,
    output_stream: TextIO | None = None,
    payload: Mapping[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
    fresh_tool_call_authority_provider: (
        Callable[[], tuple[GuardConfig, GuardArtifact, str, object] | None] | None
    ) = None,
) -> int | None:
    if copilot_permission_request is None:
        return None
    runtime_artifact, runtime_artifact_hash, runtime_arguments = copilot_permission_request
    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=runtime_artifact,
        artifact_hash=runtime_artifact_hash,
        arguments=runtime_arguments,
        fresh_authority_provider=fresh_tool_call_authority_provider,
    )
    if decision.post_claim_authority is not None:
        config = decision.post_claim_authority.config
        runtime_artifact = decision.post_claim_authority.artifact
        runtime_artifact_hash = decision.post_claim_authority.artifact_hash
        runtime_arguments = decision.post_claim_authority.arguments
    artifact_id = runtime_artifact.artifact_id
    artifact_name = runtime_artifact.name
    policy_action = cast(
        GuardAction,
        {
            "allow": "allow",
            "warn": "allow",
            "review": "require-reapproval",
            "block": "block",
            "sandbox-required": "sandbox-required",
            "require-reapproval": "require-reapproval",
        }.get(decision.action, "require-reapproval"),
    )
    approval_reuse = _copilot_approval_reuse_evidence(decision)
    decision_scanner_evidence = _copilot_tool_decision_scanner_evidence(decision)
    saved_policy_blocks = decision.saved_action == "block"
    post_claim_failure = decision.post_claim_revalidated and policy_action != "allow"
    terminal_action = policy_action in {"block", "sandbox-required"}
    runtime_detection = _runtime_detection(args.harness, runtime_artifact)
    evaluation_payload: dict[str, object] = {
        "artifacts": [
            {
                "artifact_id": artifact_id,
                "artifact_name": artifact_name,
                "artifact_hash": runtime_artifact_hash,
                "policy_action": policy_action,
                "changed_fields": ["runtime_tool_call", *decision.signals],
                "artifact_type": runtime_artifact.artifact_type,
                "source_scope": runtime_artifact.source_scope,
                "config_path": runtime_artifact.config_path,
                "launch_target": json.dumps(runtime_arguments, sort_keys=True)
                if runtime_arguments is not None
                else runtime_artifact.command,
                "action_envelope_json": _action_envelope_json(action_envelope),
                "scanner_evidence": list(decision_scanner_evidence),
            }
        ]
    }
    now = _now()
    response_payload: dict[str, object] = {
        "recorded": True,
        "harness": _canonical_harness_name(args.harness),
        "artifact_id": artifact_id,
        "artifact_name": artifact_name,
        "artifact_type": runtime_artifact.artifact_type,
        "policy_action": policy_action,
        "risk_signals": list(decision.signals),
        "risk_summary": decision.summary,
        "launch_summary": json.dumps(runtime_arguments, sort_keys=True)
        if runtime_arguments is not None
        else runtime_artifact.command,
    }
    if approval_reuse is not None:
        response_payload["approval_reuse"] = approval_reuse
    if decision_scanner_evidence:
        response_payload["scanner_evidence"] = list(decision_scanner_evidence)
    if config.mode == "observe" and policy_action != "allow" and not saved_policy_blocks and not post_claim_failure:
        queued = (
            []
            if terminal_action
            else _queue_observed_copilot_approval(
                artifact=runtime_artifact,
                artifact_hash=runtime_artifact_hash,
                artifact_name=artifact_name,
                args=args,
                action_envelope=action_envelope,
                config=config,
                context=context,
                decision=decision,
                guard_home=guard_home,
                managed_install=managed_install,
                payload=payload,
                runtime_arguments=runtime_arguments,
                runtime_workspace=runtime_workspace,
                store=store,
            )
        )
        response_payload["approval_requests"] = queued
        if terminal_action:
            response_payload["observed_terminal_action"] = policy_action
        policy_action = "allow"
        response_payload["policy_action"] = "allow"
    if policy_action == "allow":
        receipt = allow_tool_call(
            store=store,
            artifact=runtime_artifact,
            artifact_hash=runtime_artifact_hash,
            decision_source=decision.source,
            now=now,
            signals=decision.signals,
            risk_categories=decision.risk_categories,
            remember=False,
            arguments=runtime_arguments,
            additional_scanner_evidence=decision_scanner_evidence,
        )
        _record_copilot_pre_activity(
            store=store,
            context=context,
            event="copilotPermissionRequest",
            payload=payload,
            policy_action=policy_action,
            receipt_id=receipt.receipt_id,
            decision=decision,
            runtime_workspace=runtime_workspace,
        )
        if _should_emit_copilot_hook_response(args):
            _record_harness_usage_for_hook(
                store=store,
                action_envelope=action_envelope,
                payload=payload,
                policy_action=policy_action,
            )
            _emit_copilot_permission_request_response(
                behavior="allow",
                approval_reuse=approval_reuse,
                scanner_evidence=decision_scanner_evidence,
                output_stream=output_stream,
            )
            return 0
        _record_harness_usage_for_hook(
            store=store,
            action_envelope=action_envelope,
            payload=payload,
            policy_action=policy_action,
        )
        _emit("hook", response_payload, getattr(args, "json", False))
        return 0
    receipt = block_tool_call(
        store=store,
        artifact=runtime_artifact,
        artifact_hash=runtime_artifact_hash,
        decision_source="permission-request-hook",
        now=now,
        signals=decision.signals,
        risk_categories=decision.risk_categories,
        arguments=runtime_arguments,
        additional_scanner_evidence=decision_scanner_evidence,
        policy_action=policy_action,
    )
    _record_copilot_pre_activity(
        store=store,
        context=context,
        event="copilotPermissionRequest",
        payload=payload,
        policy_action=policy_action,
        receipt_id=receipt.receipt_id,
        decision=decision,
        runtime_workspace=runtime_workspace,
    )
    if terminal_action:
        response_payload["approval_requests"] = []
        response_payload["terminal"] = True
        response_payload["terminal_action"] = policy_action
        _record_harness_usage_for_hook(
            store=store,
            action_envelope=action_envelope,
            payload=payload,
            policy_action=policy_action,
        )
        if _should_emit_copilot_hook_response(args):
            _emit_copilot_permission_request_response(
                behavior="deny",
                message=f"HOL Guard blocked {artifact_name}. {decision.summary}",
                interrupt=True,
                approval_reuse=approval_reuse,
                scanner_evidence=decision_scanner_evidence,
                output_stream=output_stream,
            )
            return 0
        _emit("hook", response_payload, getattr(args, "json", False))
        return 1
    approval_center_url = ensure_guard_daemon(guard_home)
    approval_flow = get_adapter(args.harness).approval_flow(managed_install=managed_install)
    try:
        daemon_client = load_guard_surface_daemon_client(guard_home)
    except RuntimeError:
        queued = queue_blocked_approvals(
            redaction_level=config.receipt_redaction_level,
            detection=runtime_detection,
            evaluation=evaluation_payload,
            store=store,
            approval_center_url=approval_center_url,
            now=now,
        )
    else:
        session = daemon_client.start_session(
            harness=args.harness,
            surface="harness-adapter",
            workspace=str(runtime_workspace) if runtime_workspace else None,
            client_name=f"{args.harness}-permission-hook",
            client_title=f"{args.harness} permission hook",
            client_version="1.0.0",
            capabilities=["approval-resolution", "receipt-view"],
        )
        blocked_operation = daemon_client.queue_blocked_operation(
            session_id=str(session["session_id"]),
            operation_type="tool_call",
            harness=args.harness,
            metadata={
                "tool_name": str(payload.get("tool_name", "")),
                "hook_name": "permissionRequest",
                "hook_event_name": "PermissionRequest",
                **_codex_browser_wait_metadata(
                    args=args,
                    event_name="PermissionRequest",
                    policy_action=policy_action,
                    config=config,
                    payload=payload,
                ),
                "command_text": _hook_command_text(payload),
                "workspace": str(runtime_workspace) if runtime_workspace else None,
            },
            detection=runtime_detection.to_dict(),
            evaluation=evaluation_payload,
            approval_center_url=approval_center_url,
            approval_surface_policy=_approval_surface_policy_for_flow(
                config.approval_surface_policy,
                approval_flow,
            ),
            open_key=artifact_id,
            redaction_level=config.receipt_redaction_level,
        )
        operation = blocked_operation.get("operation")
        if not isinstance(operation, dict):
            operation = {}
        queued = blocked_operation.get("approval_requests")
        if not isinstance(queued, list):
            queued = []
        operation_id = _optional_string(operation.get("operation_id"))
        if operation_id is not None:
            response_payload["operation_id"] = operation_id
        response_payload["operation"] = operation
        approval_request_ids = operation.get("approval_request_ids")
        if isinstance(approval_request_ids, list):
            response_payload["approval_request_ids"] = approval_request_ids
    response_payload["approval_requests"] = queued
    _attach_primary_approval_link(
        response_payload,
        harness=_optional_string(args.harness) or args.harness,
        approval_center_url=approval_center_url,
    )
    response_payload["approval_center_url"] = approval_center_url
    response_payload["review_hint"] = approval_center_hint(
        context=context,
        harness=args.harness,
        approval_center_url=approval_center_url,
        queued=queued,
        managed_install=managed_install,
        request_id=_optional_string(response_payload.get("primary_approval_request_id")),
        artifact_id=_optional_string(response_payload.get("artifact_id")),
        review_url=_preferred_approval_review_url(response_payload, harness=args.harness),
    )
    _localize_pending_approval_copy(response_payload, harness=args.harness)
    _record_harness_usage_for_hook(
        store=store,
        action_envelope=action_envelope,
        payload=payload,
        policy_action=policy_action,
    )
    if _should_emit_copilot_hook_response(args):
        review_context = _native_approval_center_context(response_payload, harness=args.harness)
        _emit_copilot_permission_request_response(
            behavior="deny",
            message=_copilot_hook_reason(
                f"HOL Guard blocked {artifact_name}. {decision.summary}",
                review_context,
            ),
            interrupt=True,
            approval_reuse=approval_reuse,
            scanner_evidence=decision_scanner_evidence,
            output_stream=output_stream,
        )
        return 0
    _emit("hook", response_payload, getattr(args, "json", False))
    return 1


__all__ = [
    "_run_hook_copilot_permission_request",
    "_run_hook_copilot_pretool",
]
