"""Guard CLI Copilot hook transport.

The resident ``hook_decide`` op settles the Copilot tool call and names the
effects to run; this module runs them in order and writes the response.
"""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .commands_support import *

if TYPE_CHECKING:
    from ._commands_shared import _hook_command_text, _now
    from .commands_support_hook_payload import (
        _action_envelope_json,
        _approval_surface_policy_for_flow,
        _write_json_line,
    )
    from .commands_support_interaction import (
        _bind_hook_blocked_operation_queue,
        _codex_browser_wait_metadata,
        _preferred_approval_review_url,
        _record_harness_usage_for_hook,
    )
    from .commands_support_prompts import _copilot_hook_reason, _emit_copilot_permission_request_response
    from .commands_support_runtime_artifacts import _optional_string
    from .commands_support_runtime_policy import _localize_pending_approval_copy, _native_approval_center_context
    from .commands_support_runtime_resolution import _canonical_harness_name, _runtime_detection


from ..harness_posture import harness_is_recording_only, harness_posture_override
from ..native_hook_decision import NativeHookDecisionError, native_copilot_settle
from ..native_retry_lineage import capture_retry_lineage
from ..runtime.command_activity_contract import ActivityApprovalReuseStatus
from ._commands_shared import *
from .commands_parser_helpers import *
from .commands_support_command_activity import record_pre_hook_command_activity_best_effort
from .commands_support_observe_queue import queue_observe_mode_request


def run_native_copilot_pretool(
    args: argparse.Namespace,
    *,
    action_envelope: GuardActionEnvelope | None,
    config: GuardConfig,
    context: HarnessContext,
    copilot_runtime_tool_call: tuple[GuardArtifact, str, object],
    output_stream: TextIO | None = None,
    payload: Mapping[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
    fresh_tool_call_authority_provider: (
        Callable[[], tuple[GuardConfig, GuardArtifact, str, object] | None] | None
    ) = None,
    native_edge_result: Mapping[str, object] | None = None,
) -> int:
    return _settle_copilot_tool_call(
        args,
        stage="pre_tool_use",
        tool_call=copilot_runtime_tool_call,
        action_envelope=action_envelope,
        config=config,
        context=context,
        output_stream=output_stream,
        payload=payload,
        runtime_workspace=runtime_workspace,
        store=store,
        fresh_tool_call_authority_provider=fresh_tool_call_authority_provider,
        native_edge_result=native_edge_result,
    )


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
    return _settle_copilot_tool_call(
        args,
        stage="permission_request",
        tool_call=copilot_permission_request,
        action_envelope=action_envelope,
        config=config,
        context=context,
        output_stream=output_stream,
        payload=payload,
        runtime_workspace=runtime_workspace,
        store=store,
        fresh_tool_call_authority_provider=fresh_tool_call_authority_provider,
        guard_home=guard_home,
        managed_install=managed_install,
    )


def _settle_copilot_tool_call(
    args: argparse.Namespace,
    *,
    stage: str,
    tool_call: tuple[GuardArtifact, str, object],
    action_envelope: GuardActionEnvelope | None,
    config: GuardConfig,
    context: HarnessContext,
    output_stream: TextIO | None,
    payload: Mapping[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
    fresh_tool_call_authority_provider: Callable[[], tuple[GuardConfig, GuardArtifact, str, object] | None] | None,
    native_edge_result: Mapping[str, object] | None = None,
    guard_home: Path | None = None,
    managed_install: dict[str, object] | None = None,
) -> int:
    from ..blocked_request_mode import asks_for_approval
    from ..native_policy_snapshot_acked import recording_only_from_acked_snapshot

    runtime_artifact, runtime_artifact_hash, runtime_arguments = tool_call
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
    plan = native_copilot_settle(
        {
            "stage": stage,
            "harness_is_copilot": args.harness == "copilot",
            "decision": {
                "action": decision.action,
                "source": decision.source,
                "summary": decision.summary,
                "signals": list(decision.signals),
                "normalization_reason_code": decision.normalization_reason_code,
                "original_action": decision.original_action,
                "approval_reuse_status": decision.approval_reuse_status,
                "approval_reuse_reason_code": decision.approval_reuse_reason_code,
                "current_action": decision.current_action,
                "saved_action": decision.saved_action,
            },
            "artifact": {
                "artifact_id": runtime_artifact.artifact_id,
                "artifact_name": runtime_artifact.name,
                "artifact_hash": runtime_artifact_hash,
                "artifact_type": runtime_artifact.artifact_type,
                "source_scope": runtime_artifact.source_scope,
                "config_path": runtime_artifact.config_path,
                "launch_target": (
                    json.dumps(runtime_arguments, sort_keys=True)
                    if runtime_arguments is not None
                    else runtime_artifact.command
                ),
                "action_envelope_json": _action_envelope_json(action_envelope),
                "canonical_harness": _canonical_harness_name(args.harness),
            },
            "native_edge": native_edge_result if isinstance(native_edge_result, Mapping) else None,
            "recording_only": harness_is_recording_only(config, "copilot"),
            "posture_watch": harness_posture_override(config, "copilot") == "watch",
            "asks_for_approval": asks_for_approval(config),
        },
        lambda: recording_only_from_acked_snapshot(store, "copilot"),
        guard_home=store.guard_home,
    )
    approval_reuse = plan["approval_reuse"]
    scanner_evidence = tuple(plan["scanner_evidence"])
    now = _now()
    receipt_id = ""
    for effect in plan["effects"]:
        kind = effect["effect"]
        if kind == "silent_review":
            from ..approvals import record_unprompted_review

            record_unprompted_review(
                detection=_runtime_detection(args.harness, runtime_artifact),
                evaluation={"artifacts": [effect["artifact"]]},
                store=store,
                redaction_level=config.receipt_redaction_level,
            )
        elif kind == "observe_queue":
            queue_observe_mode_request(
                action_envelope=action_envelope,
                artifact=runtime_artifact,
                artifact_hash=runtime_artifact_hash,
                changed_fields=tuple(effect["changed_fields"]),
                executable_action=effect["executable_action"],
                observed_policy_action=effect["observed_policy_action"],
                redaction_level=config.receipt_redaction_level,
                risk_summary=decision.summary,
                scanner_evidence=scanner_evidence,
                store=store,
            )
        elif kind == "receipt":
            receipt_kwargs: dict[str, Any] = {
                "store": store,
                "artifact": runtime_artifact,
                "artifact_hash": runtime_artifact_hash,
                "decision_source": effect["decision_source"],
                "now": now,
                "signals": decision.signals,
                "risk_categories": decision.risk_categories,
                "arguments": runtime_arguments,
                "additional_scanner_evidence": scanner_evidence,
                "policy_action": effect["policy_action"],
            }
            if effect["verdict"] == "allow":
                receipt = allow_tool_call(remember=False, **receipt_kwargs)
            else:
                receipt = block_tool_call(**receipt_kwargs)
            receipt_id = receipt.receipt_id
        elif kind == "activity":
            _ = record_pre_hook_command_activity_best_effort(
                store=store,
                guard_home=context.guard_home,
                harness="copilot",
                event=effect["event"],
                payload=payload,
                policy_action=effect["policy_action"],
                receipt_id=receipt_id,
                prompted=effect["prompted"],
                approval_reuse_status=ActivityApprovalReuseStatus(effect["reuse_status"]),
                cwd=runtime_workspace,
                home_dir=context.home_dir,
            )
        elif kind == "usage":
            _record_harness_usage_for_hook(
                store=store,
                action_envelope=action_envelope,
                payload=payload,
                policy_action=effect["policy_action"],
            )
        elif kind == "pretool_response":
            _emit_copilot_pretool_response(
                args,
                permission_decision=effect["permission_decision"],
                reason=effect["reason"],
                approval_reuse=approval_reuse,
                scanner_evidence=scanner_evidence,
                output_stream=output_stream,
            )
        elif kind == "permission_response":
            _emit_copilot_permission_request_response(
                behavior=effect["behavior"],
                message=effect["message"],
                interrupt=effect["interrupt"],
                approval_reuse=approval_reuse,
                scanner_evidence=scanner_evidence,
                output_stream=output_stream,
            )
        elif kind == "queue_approval":
            if guard_home is None:
                raise NativeHookDecisionError("native_hook_decision_payload_invalid")
            _queue_copilot_approval(
                args,
                effect=effect,
                policy_action=plan["policy_action"],
                runtime_artifact=runtime_artifact,
                approval_reuse=approval_reuse,
                scanner_evidence=scanner_evidence,
                config=config,
                context=context,
                guard_home=guard_home,
                managed_install=managed_install,
                now=now,
                output_stream=output_stream,
                payload=payload,
                runtime_workspace=runtime_workspace,
                store=store,
                action_envelope=action_envelope,
            )
        else:
            raise NativeHookDecisionError("native_hook_decision_payload_invalid")
    return plan["exit_code"]


def _emit_copilot_pretool_response(
    args: argparse.Namespace,
    *,
    permission_decision: str,
    reason: str,
    approval_reuse: dict[str, object] | None,
    scanner_evidence: tuple[dict[str, object], ...],
    output_stream: TextIO | None,
) -> None:
    # Copilot's command-hook contract only accepts its native transport
    # fields; the exact Guard action lives in Guard receipts and events.
    doc: dict[str, object]
    if not getattr(args, "json", False):
        doc = {"permissionDecision": permission_decision}
        if permission_decision != "allow":
            doc["permissionDecisionReason"] = reason
    elif permission_decision == "allow":
        _write_json_line({"permissionDecision": "allow"}, output_stream=output_stream)
        return
    else:
        doc = {
            "continue": True,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": permission_decision,
                "permissionDecisionReason": reason,
            },
        }
    if approval_reuse is not None:
        doc["approval_reuse"] = approval_reuse
    if scanner_evidence:
        doc["scanner_evidence"] = list(scanner_evidence)
    _write_json_line(doc, output_stream=output_stream)


def _queue_copilot_approval(
    args: argparse.Namespace,
    *,
    effect: Mapping[str, Any],
    policy_action: str,
    runtime_artifact: GuardArtifact,
    approval_reuse: dict[str, object] | None,
    scanner_evidence: tuple[dict[str, object], ...],
    config: GuardConfig,
    context: HarnessContext,
    guard_home: Path,
    managed_install: dict[str, object] | None,
    now: str,
    output_stream: TextIO | None,
    payload: Mapping[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
    action_envelope: GuardActionEnvelope | None,
) -> None:
    artifact_id = runtime_artifact.artifact_id
    runtime_detection = _runtime_detection(args.harness, runtime_artifact)
    evaluation_payload: dict[str, object] = {"artifacts": [dict(effect["evaluation_artifact"])]}
    response_payload: dict[str, object] = dict(effect["response_payload"])
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
        guard_home=guard_home,
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
        try:
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
        except (RuntimeError, OSError) as queue_error:
            # A local queue past a native or store deadline (TimeoutError) keeps the deny.
            queued = approvals_queued_before(queue_error)
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
        message=_copilot_hook_reason(effect["deny_reason"], review_context),
        interrupt=True,
        approval_reuse=approval_reuse,
        scanner_evidence=scanner_evidence,
        output_stream=output_stream,
    )


__all__ = [
    "run_native_copilot_permission_request",
    "run_native_copilot_pretool",
]
