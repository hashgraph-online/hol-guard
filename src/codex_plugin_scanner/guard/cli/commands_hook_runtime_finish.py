"""Guard CLI runtime artifact hook final response flow."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .commands_support_claude_approval import _claude_native_pretooluse_terminal_notice
    from .commands_support_hook_payload import (
        _emit_native_hook_block_stderr,
        _emit_native_hook_notification_stderr,
        _emit_native_hook_response,
    )
    from .commands_support_interaction import (
        _codex_browser_approval_decision,
        _emit,
        _record_harness_usage_for_hook,
        _should_emit_claude_native_pretooluse_notice,
        _should_emit_copilot_hook_response,
        _should_emit_native_hook_exit_block,
        _should_emit_native_hook_json_response,
        _should_emit_native_hook_response,
    )
    from .commands_support_prompts import (
        _claude_prompt_system_message,
        _codex_prompt_block_system_message,
        _copilot_hook_reason,
        _emit_copilot_hook_response,
        _runtime_artifact_native_reason,
    )
    from .commands_support_runtime_policy import (
        _native_approval_center_context,
        _native_hook_reason,
        _native_hook_reason_for_harness,
    )
    from .commands_support_runtime_resolution import _canonical_harness_name


from ._commands_shared import *
from .commands_parser_helpers import *

from .commands_hook_runtime_state import (
    RuntimeArtifactHookState,
    record_runtime_artifact_hook_receipt,
    set_runtime_artifact_hook_final_action,
)

def _finalize_runtime_artifact_hook(
    state: RuntimeArtifactHookState,
    args: argparse.Namespace,
    *,
    config: GuardConfig,
    output_stream: TextIO | None = None,
    payload: Mapping[str, object],
    store: GuardStore,
    post_wait_revalidator: Callable[[], RuntimeArtifactHookState | None] | None = None,
) -> int:
    action_envelope = state.action_envelope
    event_name = state.event_name
    policy_action = state.policy_action
    response_payload = state.response_payload
    runtime_artifact = state.runtime_artifact
    if _should_emit_copilot_hook_response(args):
        record_runtime_artifact_hook_receipt(state, store)
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
                response_payload.get("review_hint"),
                response_payload.get("risk_headline"),
            ),
            output_stream=output_stream,
        )
        return 0
    fresh_state: RuntimeArtifactHookState | None = None

    def fresh_browser_context() -> Mapping[str, object] | None:
        nonlocal fresh_state
        if post_wait_revalidator is None:
            return None
        fresh_state = post_wait_revalidator()
        if fresh_state is None:
            return None
        composition = fresh_state.response_payload.get("policy_composition")
        current_action = (
            composition.get("current_composed_action")
            if isinstance(composition, Mapping)
            else None
        )
        return {
            "artifact_id": fresh_state.artifact_id,
            "artifact_hash": fresh_state.runtime_artifact_hash,
            "current_action": current_action,
            "authoritative_action": fresh_state.policy_action,
        }

    codex_browser_decision = _codex_browser_approval_decision(
        args=args,
        event_name=event_name,
        policy_action=policy_action,
        response_payload=response_payload,
        store=store,
        config=config,
        daemon_client=state.browser_approval_daemon_client,
        expected_artifact_hash=state.runtime_artifact_hash,
        fresh_context_provider=fresh_browser_context,
    )

    def adopt_fresh_browser_state() -> None:
        nonlocal action_envelope, event_name, policy_action, response_payload, runtime_artifact, state
        if fresh_state is None or fresh_state is state:
            return
        previous_response = response_payload
        previous_initial_action = state.initial_policy_action
        previous_daemon_client = state.browser_approval_daemon_client
        state = fresh_state
        state.initial_policy_action = previous_initial_action
        state.browser_approval_daemon_client = previous_daemon_client
        for key in (
            "approval_request_ids",
            "approval_requests",
            "approval_url",
            "approval_url_terminal",
            "approval_wait",
            "browser_resolution_request_id",
            "browser_resolution_validation",
            "codex_resume",
            "continuation",
            "operation",
            "operation_id",
            "operation_status",
            "review_hint",
            "session_id",
        ):
            if key in previous_response:
                state.response_payload[key] = previous_response[key]
        action_envelope = state.action_envelope
        event_name = state.event_name
        policy_action = state.policy_action
        response_payload = state.response_payload
        runtime_artifact = state.runtime_artifact

    if codex_browser_decision == "allow":
        adopt_fresh_browser_state()
        approval_request_id = response_payload.get("browser_resolution_request_id")
        set_runtime_artifact_hook_final_action(
            state,
            "allow",
            approval_request_id=(
                approval_request_id if isinstance(approval_request_id, str) else None
            ),
            approval_source="browser",
        )
        action_envelope = state.action_envelope
        policy_action = state.policy_action
        response_payload = state.response_payload
        if event_name != "PreToolUse":
            _emit_native_hook_response(
                harness=args.harness,
                policy_action="allow",
                event_name=event_name,
                reason="",
                output_stream=output_stream,
            )
        record_runtime_artifact_hook_receipt(state, store)
        _record_harness_usage_for_hook(
            store=store,
            action_envelope=action_envelope,
            payload=payload,
            policy_action="allow",
        )
        return 0
    if codex_browser_decision in {"block", "sandbox-required"}:
        adopt_fresh_browser_state()
        approval_request_id = response_payload.get("browser_resolution_request_id")
        if not isinstance(approval_request_id, str):
            approval_requests = response_payload.get("approval_requests")
            if isinstance(approval_requests, list) and approval_requests:
                first_request = approval_requests[0]
                if isinstance(first_request, dict) and isinstance(first_request.get("request_id"), str):
                    approval_request_id = first_request["request_id"]
        set_runtime_artifact_hook_final_action(
            state,
            codex_browser_decision,
            approval_request_id=(
                approval_request_id if isinstance(approval_request_id, str) else None
            ),
            approval_source="browser",
        )
        action_envelope = state.action_envelope
        policy_action = state.policy_action
        response_payload = state.response_payload
    record_runtime_artifact_hook_receipt(state, store)
    approval_context = _native_approval_center_context(response_payload, harness=args.harness)
    raw_runtime_reason = _runtime_artifact_native_reason(runtime_artifact, response_payload)
    if _should_emit_native_hook_exit_block(args, event_name=event_name, policy_action=policy_action):
        if _canonical_harness_name(args.harness) == "codex" and approval_context is not None:
            native_block_reason = _native_hook_reason(raw_runtime_reason, approval_context)
        else:
            native_block_reason = _native_hook_reason_for_harness(
                args.harness,
                raw_runtime_reason,
                approval_context,
            )
        if _canonical_harness_name(args.harness) == "kimi":
            _emit_native_hook_response(
                harness=args.harness,
                policy_action=policy_action,
                event_name=event_name,
                reason=native_block_reason,
                output_stream=output_stream,
            )
        elif _canonical_harness_name(args.harness) == "grok":
            from ..adapters.grok_hooks import emit_grok_hook_response

            emit_grok_hook_response(
                policy_action=policy_action,
                reason=native_block_reason,
                output_stream=output_stream,
            )
        elif _canonical_harness_name(args.harness) == "pi":
            from ..adapters.pi_hooks import emit_pi_hook_response

            emit_pi_hook_response(
                policy_action=policy_action,
                reason=native_block_reason,
                approval_payload=response_payload,
                output_stream=output_stream,
            )
        elif _canonical_harness_name(args.harness) == "adal":
            from ..adapters.adal_hooks import emit_adal_hook_response

            emit_adal_hook_response(
                policy_action=policy_action,
                reason=native_block_reason,
                event_name=event_name,
                payload=payload,
                output_stream=output_stream,
            )
        elif _canonical_harness_name(args.harness) == "zcode":
            from ..adapters.zcode_hooks import emit_zcode_hook_response

            emit_zcode_hook_response(
                policy_action=policy_action,
                reason=native_block_reason,
                event_name=event_name,
                payload=payload,
                output_stream=output_stream,
            )
        # Kimi surfaces stderr to the user as the blocking explanation.
        _emit_native_hook_block_stderr(native_block_reason)
        _record_harness_usage_for_hook(
            store=store,
            action_envelope=action_envelope,
            payload=payload,
            policy_action=policy_action,
        )
        return 2
    if _canonical_harness_name(args.harness) == "codex" and (
        event_name == "UserPromptSubmit"
        or approval_context is not None
        or policy_action in {"block", "sandbox-required"}
    ):
        runtime_reason = _native_hook_reason(
            raw_runtime_reason,
            approval_context or response_payload.get("review_hint"),
        )
    else:
        runtime_reason = _native_hook_reason_for_harness(
            args.harness,
            raw_runtime_reason,
            approval_context,
        )
    if _should_emit_claude_native_pretooluse_notice(
        args,
        event_name=event_name,
        policy_action=policy_action,
    ):
        _emit_native_hook_notification_stderr(
            _claude_native_pretooluse_terminal_notice(payload=dict(payload), reason=runtime_reason)
        )
    if _should_emit_native_hook_response(args) or _should_emit_native_hook_json_response(
        args,
        event_name=event_name,
        output_stream=output_stream,
    ):
        system_message = None
        canonical_harness = _canonical_harness_name(args.harness)
        if canonical_harness == "claude-code":
            system_message = _claude_prompt_system_message(
                event_name=event_name,
                policy_action=policy_action,
                artifact=runtime_artifact,
                native_reason=runtime_reason,
            )
        elif canonical_harness == "codex" and event_name == "UserPromptSubmit":
            system_message = _codex_prompt_block_system_message(
                policy_action=policy_action,
                native_reason=runtime_reason,
            )
        if canonical_harness == "grok":
            from ..adapters.grok_hooks import emit_grok_hook_response

            emit_grok_hook_response(
                policy_action=policy_action,
                reason=runtime_reason,
                output_stream=output_stream,
            )
            _record_harness_usage_for_hook(
                store=store,
                action_envelope=action_envelope,
                payload=payload,
                policy_action=policy_action,
            )
            return 0 if policy_action not in {"review", "require-reapproval", "sandbox-required", "block"} else 2
        if canonical_harness == "pi":
            from ..adapters.pi_hooks import emit_pi_hook_response

            emit_pi_hook_response(
                policy_action=policy_action,
                reason=runtime_reason,
                approval_payload=response_payload,
                output_stream=output_stream,
            )
            _record_harness_usage_for_hook(
                store=store,
                action_envelope=action_envelope,
                payload=payload,
                policy_action=policy_action,
            )
            return 0 if policy_action not in {"review", "require-reapproval", "sandbox-required", "block"} else 2
        if canonical_harness == "adal":
            from ..adapters.adal_hooks import adal_hook_should_block, emit_adal_hook_response

            emit_adal_hook_response(
                policy_action=policy_action,
                reason=runtime_reason,
                event_name=event_name,
                payload=payload,
                output_stream=output_stream,
            )
            _record_harness_usage_for_hook(
                store=store,
                action_envelope=action_envelope,
                payload=payload,
                policy_action=policy_action,
            )
            return (
                2
                if adal_hook_should_block(
                    policy_action=policy_action,
                    event_name=event_name,
                )
                else 0
            )
        if canonical_harness == "zcode":
            from ..adapters.zcode_hooks import emit_zcode_hook_response

            emit_zcode_hook_response(
                policy_action=policy_action,
                reason=runtime_reason,
                event_name=event_name,
                payload=payload,
                output_stream=output_stream,
            )
            _record_harness_usage_for_hook(
                store=store,
                action_envelope=action_envelope,
                payload=payload,
                policy_action=policy_action,
            )
            return 0 if policy_action not in {"review", "require-reapproval", "sandbox-required", "block"} else 2
        _emit_native_hook_response(
            harness=args.harness,
            policy_action=policy_action,
            event_name=event_name,
            reason=runtime_reason,
            system_message=system_message,
            output_stream=output_stream,
        )
        _record_harness_usage_for_hook(
            store=store,
            action_envelope=action_envelope,
            payload=payload,
            policy_action=policy_action,
        )
        return 0
    _emit("hook", response_payload, getattr(args, "json", False))
    _record_harness_usage_for_hook(
        store=store,
        action_envelope=action_envelope,
        payload=payload,
        policy_action=policy_action,
    )
    return 1 if policy_action in {"review", "require-reapproval", "sandbox-required", "block"} else 0

__all__ = [
    "_finalize_runtime_artifact_hook",
]
