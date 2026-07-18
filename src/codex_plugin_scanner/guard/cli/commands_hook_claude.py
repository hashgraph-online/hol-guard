"""Guard CLI Claude hook helpers."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _now
    from .commands_support_claude_approval import (
        _claude_guard_approval_question_message,
        _claude_permission_notice_prefers_ask_user_question,
        _claude_permission_prompt_additional_context,
        _claude_permission_prompt_system_message,
        _claude_permission_prompt_terminal_notice,
        _claude_permission_request_additional_context,
        _claude_permission_request_system_message,
        _claude_permission_request_terminal_notice,
        _is_claude_permission_prompt_notification,
        _is_claude_permission_request,
        _resolve_claude_permission_request_policy_action,
    )
    from .commands_support_hook_payload import _emit_native_hook_notification_stderr, _emit_native_hook_response
    from .commands_support_hook_state import (
        _emit_claude_permission_request_passthrough,
        _load_claude_permission_notice,
        _mark_claude_pending_permission_prompt_seen,
        _peek_claude_permission_notice,
    )
    from .commands_support_prompts import _runtime_artifact_native_reason
    from .commands_support_runtime_artifacts import _optional_string


from ._commands_shared import *
from .commands_parser_helpers import *


def _run_hook_claude_permission_request(
    args: argparse.Namespace,
    *,
    config: GuardConfig,
    output_stream: TextIO | None = None,
    payload: Mapping[str, object],
    runtime_artifact: GuardArtifact | None,
    runtime_workspace: Path | None,
    store: GuardStore,
) -> int | None:
    payload_map = dict(payload)
    if not _is_claude_permission_request(args, payload_map):
        return None
    notice = _peek_claude_permission_notice(store, payload_map)
    if notice is not None:
        _mark_claude_pending_permission_prompt_seen(store=store, payload=payload_map, notice=notice)
    if notice is not None and _claude_permission_notice_prefers_ask_user_question(notice):
        _emit_native_hook_response(
            harness=args.harness,
            policy_action="block",
            event_name="PermissionRequest",
            reason="HOL Guard is routing this approval through AskUserQuestion.",
            system_message=_claude_permission_prompt_system_message(payload=payload_map, notice=notice),
            additional_context=_claude_guard_approval_question_message(notice),
            output_stream=output_stream,
        )
        return 0
    native_reason: str | None = None
    policy_action: str | None = None
    if notice is not None:
        policy_action = "require-reapproval"
        native_reason = _optional_string(notice.get("reason"))
    elif runtime_artifact is not None:
        policy_action, reason_stub = _resolve_claude_permission_request_policy_action(
            config=config,
            store=store,
            args=args,
            runtime_artifact=runtime_artifact,
            runtime_workspace=runtime_workspace,
        )
        if policy_action not in {"review", "require-reapproval", "sandbox-required", "block"}:
            _emit_claude_permission_request_passthrough(output_stream=output_stream)
            return 0
        native_reason = _runtime_artifact_native_reason(runtime_artifact, reason_stub)
    else:
        _emit_claude_permission_request_passthrough(output_stream=output_stream)
        return 0
    if native_reason is None or not native_reason.strip():
        native_reason = "HOL Guard is reviewing this Claude approval prompt."
    if not getattr(args, "json", False):
        _emit_native_hook_notification_stderr(
            _claude_permission_request_terminal_notice(
                payload=payload_map,
                native_reason=native_reason,
            )
        )
    if policy_action in {"block", "sandbox-required"}:
        _emit_native_hook_response(
            harness=args.harness,
            policy_action=policy_action,
            event_name="PermissionRequest",
            reason=native_reason,
            system_message=_claude_permission_request_system_message(
                payload=payload_map,
                native_reason=native_reason,
            ),
            additional_context=_claude_permission_request_additional_context(native_reason),
            output_stream=output_stream,
        )
        return 0
    _emit_native_hook_response(
        harness=args.harness,
        policy_action="require-reapproval",
        event_name="PermissionRequest",
        reason=native_reason,
        system_message=_claude_permission_request_system_message(
            payload=payload_map,
            native_reason=native_reason,
        ),
        additional_context=_claude_permission_request_additional_context(native_reason),
        output_stream=output_stream,
    )
    return 0


def _run_hook_claude_permission_prompt_notification(
    args: argparse.Namespace,
    *,
    output_stream: TextIO | None = None,
    payload: Mapping[str, object],
    store: GuardStore,
) -> int | None:
    payload_map = dict(payload)
    if not _is_claude_permission_prompt_notification(args, payload_map):
        return None
    notice = _load_claude_permission_notice(store, payload_map)
    _mark_claude_pending_permission_prompt_seen(store=store, payload=payload_map, notice=notice)
    store.add_event(
        "claude/permission_prompt",
        {
            "session_id": payload_map.get("session_id"),
            "notification_type": payload_map.get("notification_type"),
            "tool_name": payload_map.get("tool_name"),
            "notice": notice or {},
        },
        _now(),
    )
    system_message = _claude_permission_prompt_system_message(payload=payload_map, notice=notice)
    additional_context = _claude_permission_prompt_additional_context(notice)
    if not getattr(args, "json", False):
        _emit_native_hook_notification_stderr(
            _claude_permission_prompt_terminal_notice(payload=payload_map, notice=notice)
        )
    _emit_native_hook_response(
        harness=args.harness,
        policy_action="allow",
        event_name="Notification",
        reason="HOL Guard intercepted the tool request and is routing it through a HOL Guard approval prompt.",
        system_message=system_message,
        additional_context=additional_context,
        output_stream=output_stream,
    )
    return 0


__all__ = [
    "_run_hook_claude_permission_prompt_notification",
    "_run_hook_claude_permission_request",
]
