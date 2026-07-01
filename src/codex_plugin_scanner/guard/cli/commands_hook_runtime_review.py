"""Guard CLI runtime artifact hook review and queue flow."""

# ruff: noqa: F403, F405

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _hook_command_text, _now
    from .commands_support_claude_approval import _claude_native_pretooluse_terminal_notice
    from .commands_support_hook_payload import (
        _action_envelope_json,
        _approval_surface_policy_for_flow,
        _emit_native_hook_notification_stderr,
        _emit_native_hook_response,
    )
    from .commands_support_hook_state import (
        _record_claude_permission_notice,
        _should_emit_prequeue_native_hook_response,
    )
    from .commands_support_interaction import (
        _attach_primary_approval_link,
        _codex_browser_wait_metadata,
        _preferred_approval_review_url,
        _record_harness_usage_for_hook,
        _should_emit_claude_native_pretooluse_notice,
        _should_emit_copilot_hook_response,
    )
    from .commands_support_permission_store import _attach_cursor_pending_approval_request_ids
    from .commands_support_prompts import (
        _claude_prompt_additional_context,
        _claude_prompt_system_message,
        _copilot_hook_reason,
        _emit_copilot_hook_response,
        _prompt_requires_hard_block,
        _runtime_artifact_native_reason,
    )
    from .commands_support_runtime_artifacts import _optional_string
    from .commands_support_runtime_policy import _approval_delivery_payload, _localize_pending_approval_copy
    from .commands_support_runtime_resolution import (
        _canonical_harness_name,
        _runtime_detection,
        _runtime_request_summary,
    )


from ._commands_shared import *
from .commands_hook_runtime_state import RuntimeArtifactHookState
from .commands_parser_helpers import *


def _review_runtime_artifact_hook(
    state: RuntimeArtifactHookState,
    args: argparse.Namespace,
    *,
    config: GuardConfig,
    context: HarnessContext,
    guard_home: Path,
    managed_install: dict[str, object] | None,
    output_stream: TextIO | None = None,
    payload: Mapping[str, object],
    store: GuardStore,
    workspace: Path | None,
) -> int | None:
    payload_map = dict(payload)
    action_envelope = state.action_envelope
    artifact_id = state.artifact_id
    artifact_name = state.artifact_name
    changed_capabilities = state.changed_capabilities
    decision_v2_payload = state.decision_v2_payload
    event_name = state.event_name
    package_evaluation = state.package_evaluation
    policy_action = state.policy_action
    response_payload = state.response_payload
    risk_summary = state.risk_summary
    runtime_artifact = state.runtime_artifact
    runtime_artifact_hash = state.runtime_artifact_hash
    scanner_evidence_payload = state.scanner_evidence_payload
    stored_policy_action = state.stored_policy_action
    from ..adapters.cursor_hooks import cursor_hook_requires_approval_center_queue

    cursor_native_queue = _canonical_harness_name(
        args.harness
    ) == "cursor" and cursor_hook_requires_approval_center_queue(
        policy_action=policy_action,
        guard_payload=response_payload,
    )
    observe_mode = config.mode == "observe"
    if policy_action in {"block", "sandbox-required", "require-reapproval"} or cursor_native_queue:
        if observe_mode:
            should_queue_approval_center = not (policy_action == "block" and stored_policy_action == "block")
            if should_queue_approval_center:
                approval_flow = get_adapter(args.harness).approval_flow(managed_install=managed_install)
                approval_center_url = ensure_guard_daemon(guard_home)
                runtime_detection = _runtime_detection(args.harness, runtime_artifact)
                queued_policy_action = (
                    "require-reapproval"
                    if cursor_native_queue and policy_action in {"warn", "review"}
                    else policy_action
                )
                package_evaluation_to_dict = getattr(package_evaluation, "to_dict", None)
                evaluation_payload: dict[str, object] = {
                    "artifacts": [
                        {
                            "artifact_id": artifact_id,
                            "artifact_name": artifact_name,
                            "artifact_hash": runtime_artifact_hash,
                            "policy_action": queued_policy_action,
                            "changed_fields": changed_capabilities,
                            "artifact_type": runtime_artifact.artifact_type,
                            "source_scope": runtime_artifact.source_scope,
                            "config_path": runtime_artifact.config_path,
                            "launch_target": _runtime_request_summary(runtime_artifact),
                            "risk_summary": risk_summary,
                            "action_envelope_json": _action_envelope_json(action_envelope),
                            "decision_v2_json": decision_v2_payload,
                            "scanner_evidence": scanner_evidence_payload,
                            "supply_chain_evaluation": (
                                package_evaluation_to_dict() if callable(package_evaluation_to_dict) else None
                            ),
                        }
                    ]
                }
                browser_approval_daemon_client = None
                try:
                    browser_approval_daemon_client = load_guard_surface_daemon_client(guard_home)
                except RuntimeError:
                    queued = queue_blocked_approvals(
                        detection=runtime_detection,
                        evaluation=evaluation_payload,
                        store=store,
                        approval_center_url=approval_center_url,
                        now=_now(),
                        redaction_level=config.receipt_redaction_level,
                    )
                else:
                    session = browser_approval_daemon_client.start_session(
                        harness=args.harness,
                        surface="harness-adapter",
                        workspace=str(workspace) if workspace else None,
                        client_name=f"{args.harness}-hook",
                        client_title=f"{args.harness} hook",
                        client_version="1.0.0",
                        capabilities=["approval-resolution", "receipt-view"],
                    )
                    response_payload["session_id"] = str(session["session_id"])
                    blocked_operation = browser_approval_daemon_client.queue_blocked_operation(
                        session_id=str(session["session_id"]),
                        operation_type="tool_call",
                        harness=args.harness,
                        metadata={
                            "tool_name": str(payload.get("tool_name", "")),
                            "event": str(payload.get("event", "")),
                            "hook_event_name": event_name,
                            **_codex_browser_wait_metadata(
                                args=args,
                                event_name=event_name,
                                policy_action=policy_action,
                                config=config,
                                payload=payload_map,
                            ),
                            "command_text": _hook_command_text(payload_map),
                            "workspace": str(workspace) if workspace else None,
                            **(
                                codex_resume_metadata_from_hook_payload(payload_map)
                                if _canonical_harness_name(args.harness) == "codex"
                                else {}
                            ),
                        },
                        detection=runtime_detection.to_dict(),
                        evaluation=evaluation_payload,
                        approval_center_url=approval_center_url,
                        approval_surface_policy=_approval_surface_policy_for_flow(
                            config.approval_surface_policy,
                            approval_flow,
                        ),
                        open_key=_approval_open_key(args.harness, artifact_id, payload_map),
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
                response_payload["approval_delivery"] = _approval_delivery_payload(
                    args.harness,
                    managed_install=managed_install,
                )
                _localize_pending_approval_copy(response_payload, harness=args.harness)
            policy_action = "allow"
            response_payload["policy_action"] = "allow"
            state.action_envelope = action_envelope
            state.browser_approval_daemon_client = locals().get("browser_approval_daemon_client")
            state.policy_action = policy_action
            state.response_payload = response_payload
            return None
        native_reason = _runtime_artifact_native_reason(runtime_artifact, response_payload)
        additional_context = _claude_prompt_additional_context(
            harness=args.harness,
            event_name=event_name,
            policy_action=policy_action,
            artifact=runtime_artifact,
            native_reason=native_reason,
        )
        if (
            _canonical_harness_name(args.harness) == "claude-code"
            and event_name == "PreToolUse"
            and policy_action == "require-reapproval"
        ):
            _record_claude_permission_notice(
                store=store,
                payload=payload_map,
                reason=native_reason,
                artifact=runtime_artifact,
                artifact_hash=runtime_artifact_hash,
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
                reason=_copilot_hook_reason(
                    response_payload.get("why_now"),
                    response_payload.get("risk_headline"),
                    response_payload.get("path_summary"),
                ),
                output_stream=output_stream,
            )
            return 0
        if _should_emit_prequeue_native_hook_response(args, output_stream=output_stream):
            if _should_emit_claude_native_pretooluse_notice(
                args,
                event_name=event_name,
                policy_action=policy_action,
            ):
                _emit_native_hook_notification_stderr(
                    _claude_native_pretooluse_terminal_notice(payload=payload_map, reason=native_reason)
                )
            system_message = None
            if _canonical_harness_name(args.harness) == "claude-code":
                system_message = _claude_prompt_system_message(
                    event_name=event_name,
                    policy_action=policy_action,
                    artifact=runtime_artifact,
                    native_reason=native_reason,
                )
            _emit_native_hook_response(
                harness=args.harness,
                policy_action=policy_action,
                event_name=event_name,
                reason=native_reason,
                system_message=system_message,
                additional_context=additional_context,
                output_stream=output_stream,
            )
            _record_harness_usage_for_hook(
                store=store,
                action_envelope=action_envelope,
                payload=payload,
                policy_action=policy_action,
            )
            return 0
        should_queue_approval_center = not (policy_action == "block" and stored_policy_action == "block")
        if not _prompt_requires_hard_block(runtime_artifact) and should_queue_approval_center:
            approval_flow = get_adapter(args.harness).approval_flow(managed_install=managed_install)
            approval_center_url = ensure_guard_daemon(guard_home)
            runtime_detection = _runtime_detection(args.harness, runtime_artifact)
            queued_policy_action = (
                "require-reapproval" if cursor_native_queue and policy_action in {"warn", "review"} else policy_action
            )
            package_evaluation_to_dict = getattr(package_evaluation, "to_dict", None)
            evaluation_payload: dict[str, object] = {
                "artifacts": [
                    {
                        "artifact_id": artifact_id,
                        "artifact_name": artifact_name,
                        "artifact_hash": runtime_artifact_hash,
                        "policy_action": queued_policy_action,
                        "changed_fields": changed_capabilities,
                        "artifact_type": runtime_artifact.artifact_type,
                        "source_scope": runtime_artifact.source_scope,
                        "config_path": runtime_artifact.config_path,
                        "launch_target": _runtime_request_summary(runtime_artifact),
                        "risk_summary": risk_summary,
                        "action_envelope_json": _action_envelope_json(action_envelope),
                        "decision_v2_json": decision_v2_payload,
                        "scanner_evidence": scanner_evidence_payload,
                        "supply_chain_evaluation": (
                            package_evaluation_to_dict() if callable(package_evaluation_to_dict) else None
                        ),
                    }
                ]
            }
            browser_approval_daemon_client = None
            try:
                browser_approval_daemon_client = load_guard_surface_daemon_client(guard_home)
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
                session = browser_approval_daemon_client.start_session(
                    harness=args.harness,
                    surface="harness-adapter",
                    workspace=str(workspace) if workspace else None,
                    client_name=f"{args.harness}-hook",
                    client_title=f"{args.harness} hook",
                    client_version="1.0.0",
                    capabilities=["approval-resolution", "receipt-view"],
                )
                response_payload["session_id"] = str(session["session_id"])
                blocked_operation = browser_approval_daemon_client.queue_blocked_operation(
                    session_id=str(session["session_id"]),
                    operation_type="tool_call",
                    harness=args.harness,
                    metadata={
                        "tool_name": str(payload.get("tool_name", "")),
                        "event": str(payload.get("event", "")),
                        "hook_event_name": event_name,
                        **_codex_browser_wait_metadata(
                            args=args,
                            event_name=event_name,
                            policy_action=policy_action,
                            config=config,
                            payload=payload_map,
                        ),
                        "command_text": _hook_command_text(payload_map),
                        "workspace": str(workspace) if workspace else None,
                        **(
                            codex_resume_metadata_from_hook_payload(payload_map)
                            if _canonical_harness_name(args.harness) == "codex"
                            else {}
                        ),
                    },
                    detection=runtime_detection.to_dict(),
                    evaluation=evaluation_payload,
                    approval_center_url=approval_center_url,
                    approval_surface_policy=_approval_surface_policy_for_flow(
                        config.approval_surface_policy,
                        approval_flow,
                    ),
                    open_key=_approval_open_key(args.harness, artifact_id, payload_map),
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
            if (
                _canonical_harness_name(args.harness) == "cursor"
                and event_name == "PreToolUse"
                and runtime_artifact.artifact_type == "tool_action_request"
                and cursor_hook_requires_approval_center_queue(
                    policy_action=policy_action,
                    guard_payload=response_payload,
                )
            ):
                from ..adapters.cursor_hooks import cursor_hook_would_prompt_user

                if cursor_hook_would_prompt_user(
                    policy_action=policy_action,
                    guard_payload=response_payload,
                ):
                    _attach_cursor_pending_approval_request_ids(
                        store=store,
                        payload=payload_map,
                        response_payload=response_payload,
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
            response_payload["approval_delivery"] = _approval_delivery_payload(
                args.harness,
                managed_install=managed_install,
            )
            _localize_pending_approval_copy(response_payload, harness=args.harness)
    state.action_envelope = action_envelope
    state.browser_approval_daemon_client = locals().get("browser_approval_daemon_client")
    state.policy_action = policy_action
    state.response_payload = response_payload
    return None


def _approval_open_key(harness: str, artifact_id: str, payload: Mapping[str, object] | None = None) -> str:
    if _canonical_harness_name(harness) == "pi":
        runtime_open_key = (
            _optional_string(payload.get("guard_runtime_open_key"))
            if isinstance(payload, Mapping)
            else None
        )
        if runtime_open_key is not None:
            return f"pi-approval-center:{runtime_open_key}"
    return artifact_id


__all__ = [
    "_approval_open_key",
    "_review_runtime_artifact_hook",
]
