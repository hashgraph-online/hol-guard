"""Guard CLI Claude hook helpers."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from ..native_claude_permission_verdict import native_claude_permission_verdict
from ..native_hook_artifact_compose import native_hook_compose
from ..native_hook_decision import _INVALID, NativeHookDecisionError
from .commands_support import *

if TYPE_CHECKING:
    from ..runtime.package_request_evaluation import PackageRequestEvaluation
    from ._commands_shared import _now
    from .commands_support_claude_approval import (
        _claude_guard_approval_question_message,
        _claude_permission_prompt_additional_context,
        _claude_permission_prompt_system_message,
        _claude_permission_prompt_terminal_notice,
        _claude_permission_request_additional_context,
        _claude_permission_request_artifact_policy,
        _claude_permission_request_reason_stub,
        _claude_permission_request_system_message,
        _claude_permission_request_terminal_notice,
    )
    from .commands_support_hook_payload import _emit_native_hook_notification_stderr, _emit_native_hook_response
    from .commands_support_hook_state import (
        _emit_claude_permission_request_passthrough,
        _load_claude_permission_notice,
        _mark_claude_pending_permission_prompt_seen,
        _peek_claude_permission_notice,
    )
    from .commands_support_prompts import _runtime_artifact_native_reason


from ._commands_shared import *
from .commands_parser_helpers import *


def run_native_claude_permission_request(
    args: argparse.Namespace,
    *,
    config: GuardConfig,
    output_stream: TextIO | None = None,
    payload: Mapping[str, object],
    runtime_artifact: GuardArtifact | None,
    runtime_workspace: Path | None,
    store: GuardStore,
) -> int:
    """Answer Claude's permission dialog with the verdict the resident picks.

    This peeks and marks the notice, gathers the artifact policy only when the
    resident asks for it and renders the response for the verdict it returns.
    A verdict the resident cannot supply raises ``NativeHookDecisionError``.
    """

    payload_map = dict(payload)
    notice = _peek_claude_permission_notice(store, payload_map)
    if notice is not None:
        _mark_claude_pending_permission_prompt_seen(store=store, payload=payload_map, notice=notice)
    # The package evaluation behind the artifact policy, kept for the reason.
    package_evaluation: dict[str, PackageRequestEvaluation | None] = {}

    def artifact_policy() -> dict[str, object]:
        if runtime_artifact is None:
            raise NativeHookDecisionError(_INVALID)
        facts, package_evaluation["artifact"] = _claude_permission_request_artifact_policy(
            config=config,
            store=store,
            args=args,
            runtime_artifact=runtime_artifact,
            runtime_workspace=runtime_workspace,
        )
        return facts

    answer = native_claude_permission_verdict(
        notice=notice,
        runtime_artifact_present=runtime_artifact is not None,
        artifact_policy=artifact_policy,
        guard_home=store.guard_home,
    )
    if answer.verdict == "passthrough":
        _emit_claude_permission_request_passthrough(output_stream=output_stream)
        return 0
    native_reason = cast("str", answer.reason)
    if answer.verdict == "guard_question":
        _emit_native_hook_response(
            harness=args.harness,
            policy_action=cast("str", answer.policy_action),
            event_name="PermissionRequest",
            reason=native_reason,
            system_message=_claude_permission_prompt_system_message(payload=payload_map, notice=notice),
            additional_context=_claude_guard_approval_question_message(notice),
            output_stream=output_stream,
        )
        return 0
    if answer.reason_from_artifact:
        # The resident names the artifact's reason only after it asked for,
        # and was sent, that artifact's policy.
        artifact = cast("GuardArtifact", runtime_artifact)
        rendered = _runtime_artifact_native_reason(
            artifact,
            _claude_permission_request_reason_stub(
                args=args,
                runtime_artifact=artifact,
                artifact_action=cast("str", answer.artifact_action),
                package_evaluation=package_evaluation.get("artifact"),
            ),
            composer=native_hook_compose,
            guard_home=store.guard_home,
        )
        if rendered.strip():
            native_reason = rendered
    _emit_native_hook_notification_stderr(
        _claude_permission_request_terminal_notice(
            payload=payload_map,
            native_reason=native_reason,
        )
    )
    _emit_native_hook_response(
        harness=args.harness,
        policy_action=cast("str", answer.policy_action),
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


def run_native_claude_permission_prompt_notification(
    args: argparse.Namespace,
    *,
    output_stream: TextIO | None = None,
    payload: Mapping[str, object],
    store: GuardStore,
) -> int:
    payload_map = dict(payload)
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
    _emit_native_hook_notification_stderr(_claude_permission_prompt_terminal_notice(payload=payload_map, notice=notice))
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
    "run_native_claude_permission_prompt_notification",
    "run_native_claude_permission_request",
]
