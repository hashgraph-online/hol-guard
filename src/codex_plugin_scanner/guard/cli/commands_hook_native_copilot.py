"""Guard CLI Copilot hook helpers."""

# ruff: noqa: F403, F405

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from .commands_support import *

if TYPE_CHECKING:
    from ..mcp_tool_calls import ToolCallDecision
    from ._commands_shared import _hook_command_text, _now
    from .commands_support_hook_payload import (
        _action_envelope_json,
        _approval_surface_policy_for_flow,
        _copilot_hook_permission_decision,
        _write_json_line,
    )
    from .commands_support_interaction import (
        _bind_hook_blocked_operation_queue,
        _codex_browser_wait_metadata,
        _preferred_approval_review_url,
        _record_harness_usage_for_hook,
    )
    from .commands_support_prompts import (
        _copilot_hook_reason,
        _emit_copilot_hook_response,
        _emit_copilot_permission_request_response,
    )
    from .commands_support_runtime_artifacts import _optional_string
    from .commands_support_runtime_policy import _localize_pending_approval_copy, _native_approval_center_context
    from .commands_support_runtime_resolution import _canonical_harness_name, _runtime_detection


from ..action_lattice import most_restrictive_guard_action, normalize_guard_action
from ..mcp_tool_calls import resolve_tool_call_policy_action
from ..models import GuardAction
from ..retry_lineage import capture_retry_lineage
from ..runtime.command_activity_contract import ActivityApprovalReuseStatus
from ..tool_decision_evidence import tool_decision_scanner_evidence as _copilot_tool_decision_scanner_evidence
from ._commands_shared import *
from .commands_parser_helpers import *
from .commands_support_command_activity import (
    command_activity_was_prompted,
    record_pre_hook_command_activity_best_effort,
)
from .commands_support_observe_queue import queue_observe_mode_request


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
    prompted: bool | None = None,
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
        prompted=(
            prompted
            if prompted is not None
            else command_activity_was_prompted(decision.current_action or policy_action, reuse_status)
        ),
        approval_reuse_status=reuse_status,
        cwd=runtime_workspace,
        home_dir=context.home_dir,
    )


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
        "effective_action": resolve_tool_call_policy_action(decision),
    }


def run_native_copilot_pretool(
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
    native_edge_result: Mapping[str, object] | None = None,
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
    policy_action = resolve_tool_call_policy_action(decision)
    if isinstance(native_edge_result, Mapping):
        edge_action_value = native_edge_result.get("policy_action") or native_edge_result.get("minimum_action")
        if edge_action_value:
            # The edge result is an enforcement input: a present but
            # unrecognized action fails closed instead of skipping the floor.
            native_edge_action = normalize_guard_action(edge_action_value, unknown_action="block")
        elif native_edge_result.get("decision") == "deny":
            native_edge_action = "block"
        else:
            native_edge_action = None
        # PreToolUse floors only on a hard native enforcement verdict; the
        # edge's review-tier "unproven" deny is provenance here — artifact
        # adjudication, grants, and configured policy settle reviewability.
        if native_edge_action in {"block", "sandbox-required"}:
            # The native edge verdict is a non-bypassable floor on the
            # emitted Copilot decision.
            policy_action = most_restrictive_guard_action(policy_action, native_edge_action)
    approval_reuse = _copilot_approval_reuse_evidence(decision)
    decision_scanner_evidence = _copilot_tool_decision_scanner_evidence(decision)
    saved_policy_blocks = decision.saved_action == "block"
    now = _now()
    observed_policy_action: GuardAction | None = None
    if config.mode == "observe" and policy_action not in {"allow", "warn"}:
        observed_policy_action = policy_action
        observe_mode_evidence: dict[str, object] = {
            "source": "observe_mode",
            "observed_policy_action": observed_policy_action,
            "authoritative_action": "allow",
        }
        decision_scanner_evidence = (*decision_scanner_evidence, observe_mode_evidence)
        policy_action = "allow"
    if config.mode == "observe" and observed_policy_action is not None:
        queue_observe_mode_request(
            action_envelope=action_envelope,
            artifact=runtime_artifact,
            artifact_hash=runtime_artifact_hash,
            changed_fields=("runtime_tool_call", *decision.signals),
            executable_action=policy_action,
            observed_policy_action=observed_policy_action,
            redaction_level=config.receipt_redaction_level,
            risk_summary=decision.summary,
            scanner_evidence=decision_scanner_evidence,
            store=store,
        )
    from ..blocked_request_mode import asks_for_approval, safe_alternative_reason

    safe_alternative = policy_action in {"review", "require-reapproval"} and not asks_for_approval(config)
    if safe_alternative:
        policy_action = "block"
    # Copilot review/reapproval continues to PermissionRequest, which owns that
    # activity. PreToolUse records only decisions that terminate at this stage.
    if policy_action in {"allow", "warn"}:
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
            policy_action=policy_action,
        )
        if args.harness == "copilot":
            _record_copilot_pre_activity(
                store=store,
                context=context,
                event="preToolUse",
                payload=payload,
                policy_action=policy_action,
                receipt_id=receipt.receipt_id,
                decision=decision,
                runtime_workspace=runtime_workspace,
                prompted=False if safe_alternative else None,
            )
            _record_harness_usage_for_hook(
                store=store,
                action_envelope=action_envelope,
                payload=payload,
                policy_action=policy_action,
            )
            _emit_copilot_pretool_response(
                args,
                policy_action=policy_action,
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
            if args.harness == "copilot":
                _record_copilot_pre_activity(
                    store=store,
                    context=context,
                    event="preToolUse",
                    payload=payload,
                    policy_action=policy_action,
                    receipt_id=receipt.receipt_id,
                    decision=decision,
                    runtime_workspace=runtime_workspace,
                    prompted=False if safe_alternative else None,
                )
        if args.harness == "copilot":
            _record_harness_usage_for_hook(
                store=store,
                action_envelope=action_envelope,
                payload=payload,
                policy_action=policy_action,
            )
            if safe_alternative:
                denial_reason = safe_alternative_reason(decision.summary)
            elif saved_policy_blocks:
                denial_reason = f"HOL Guard blocked {runtime_artifact.name}. {decision.summary}"
            else:
                denial_reason = _copilot_hook_reason(decision.summary, runtime_artifact.name)
            _emit_copilot_pretool_response(
                args,
                policy_action=policy_action,
                reason=denial_reason,
                approval_reuse=approval_reuse,
                scanner_evidence=decision_scanner_evidence,
                output_stream=output_stream,
            )
            return 0


def _emit_copilot_pretool_response(
    args: argparse.Namespace,
    *,
    policy_action: str,
    reason: str,
    approval_reuse: dict[str, object] | None,
    scanner_evidence: Sequence[dict[str, object]],
    output_stream: Any | None,
) -> None:
    if not getattr(args, "json", False):
        _emit_copilot_hook_response(
            policy_action=policy_action,
            reason=reason,
            approval_reuse=approval_reuse,
            scanner_evidence=tuple(scanner_evidence),
            output_stream=output_stream,
        )
        return
    decision = _copilot_hook_permission_decision(policy_action)
    if decision == "allow":
        _write_json_line({"permissionDecision": "allow"}, output_stream=output_stream)
        return
    doc: dict[str, object] = {
        "continue": True,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        },
    }
    if approval_reuse is not None:
        doc["approval_reuse"] = approval_reuse
    if scanner_evidence:
        doc["scanner_evidence"] = list(scanner_evidence)
    _write_json_line(doc, output_stream=output_stream)


def run_native_copilot_permission_request(
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
    policy_action = resolve_tool_call_policy_action(decision)
    approval_reuse = _copilot_approval_reuse_evidence(decision)
    decision_scanner_evidence = _copilot_tool_decision_scanner_evidence(decision)
    from ..blocked_request_mode import asks_for_approval, safe_alternative_reason

    safe_alternative = (
        config.mode != "observe" and policy_action in {"review", "require-reapproval"} and not asks_for_approval(config)
    )
    if safe_alternative:
        policy_action = "block"
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
    observed_policy_action: GuardAction | None = None
    if config.mode == "observe" and policy_action not in {"allow", "warn"}:
        observed_policy_action = policy_action
        response_payload["approval_requests"] = []
        if terminal_action:
            response_payload["observed_terminal_action"] = policy_action
        response_payload["observed_policy_action"] = observed_policy_action
        observe_mode_evidence: dict[str, object] = {
            "source": "observe_mode",
            "observed_policy_action": observed_policy_action,
            "authoritative_action": "allow",
        }
        decision_scanner_evidence = (*decision_scanner_evidence, observe_mode_evidence)
        response_payload["scanner_evidence"] = list(decision_scanner_evidence)
        policy_action = "allow"
        response_payload["policy_action"] = "allow"
    if config.mode == "observe" and observed_policy_action is not None:
        queue_observe_mode_request(
            action_envelope=action_envelope,
            artifact=runtime_artifact,
            artifact_hash=runtime_artifact_hash,
            changed_fields=("runtime_tool_call", *decision.signals),
            executable_action=policy_action,
            observed_policy_action=observed_policy_action,
            redaction_level=config.receipt_redaction_level,
            risk_summary=decision.summary,
            scanner_evidence=decision_scanner_evidence,
            store=store,
        )
    if policy_action in {"allow", "warn"}:
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
            prompted=False if safe_alternative else None,
        )
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
        prompted=False if safe_alternative else None,
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
        _emit_copilot_permission_request_response(
            behavior="deny",
            message=(
                safe_alternative_reason(decision.summary)
                if safe_alternative
                else f"HOL Guard blocked {artifact_name}. {decision.summary}"
            ),
            interrupt=True,
            approval_reuse=approval_reuse,
            scanner_evidence=decision_scanner_evidence,
            output_stream=output_stream,
        )
        return 0
    approval_center_url = schedule_guard_daemon_ensure(
        guard_home,
        home_dir=context.home_dir,
    )
    approval_flow = get_adapter(args.harness).approval_flow(managed_install=managed_install)
    hook_metadata: dict[str, object] = {
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
    }
    retry_lineage = capture_retry_lineage(
        payload,
        harness=str(args.harness),
        workspace=str(runtime_workspace) if runtime_workspace else None,
        action_envelope=action_envelope.to_dict() if action_envelope is not None else None,
    )
    if retry_lineage is not None:
        hook_metadata["retry_lineage"] = retry_lineage
    try:
        daemon_client = load_guard_surface_daemon_client(guard_home)
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
            metadata=hook_metadata,
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
    except RuntimeError:
        queued = queue_blocked_approvals(
            redaction_level=config.receipt_redaction_level,
            detection=runtime_detection,
            evaluation=evaluation_payload,
            store=store,
            approval_center_url=approval_center_url,
            now=now,
            continuation_operation={
                "created_at": now,
                "harness": args.harness,
                "metadata": hook_metadata,
                "status": "waiting_on_approval",
                "updated_at": now,
            },
        )
        _bind_hook_blocked_operation_queue(
            harness=args.harness,
            approval_center_url=approval_center_url,
            response_payload=response_payload,
            queued=queued,
        )
    else:
        queued = _bind_hook_blocked_operation_queue(
            harness=args.harness,
            approval_center_url=approval_center_url,
            response_payload=response_payload,
            queued=[],
            blocked_operation=blocked_operation,
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


__all__ = [
    "run_native_copilot_permission_request",
    "run_native_copilot_pretool",
]
