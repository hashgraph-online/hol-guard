"""Guard CLI runtime artifact hook final response flow."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

from typing import TYPE_CHECKING


from .commands_support import *

if TYPE_CHECKING:
    from .commands_support_claude_approval import _claude_native_pretooluse_terminal_notice
    from .commands_support_hook_payload import (
        _emit_native_hook_block_stderr,
        _emit_native_hook_json_document,
        _emit_native_post_tool_envelope,
        _native_hook_json_document,
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
        _native_hook_reason,
        _native_hook_reason_for_harness,
    )
    from .commands_support_runtime_resolution import _canonical_harness_name


from ._commands_shared import *
from .commands_support_runtime_artifact_policy import (
    _runtime_artifact_fail_closed_floor,
)
from .commands_parser_helpers import *

from .commands_hook_native_state import (
    NativeArtifactHookState,
    record_native_artifact_hook_receipt,
    set_native_artifact_hook_final_action,
)


_GUIDED_POLICY_ACTIONS = frozenset({"block", "review", "require-reapproval", "sandbox-required"})


def _embedded_script_remediation(state: NativeArtifactHookState) -> str | None:
    """Guidance when a blocked/reviewed command carries an inline script body."""

    if state.policy_action not in _GUIDED_POLICY_ACTIONS:
        return None
    envelope = state.action_envelope
    command_text = envelope.command if envelope is not None else None
    if not isinstance(command_text, str):
        return None
    from ..runtime.embedded_script_evidence import (
        EMBEDDED_SCRIPT_REMEDIATION_GUIDANCE,
        command_has_embedded_script,
    )

    if command_has_embedded_script(command_text):
        return EMBEDDED_SCRIPT_REMEDIATION_GUIDANCE
    return None


def _browser_approval_decision(
    state: NativeArtifactHookState,
    args: argparse.Namespace,
    *,
    config: GuardConfig,
    store: GuardStore,
    fresh_context_provider: Callable[[], Mapping[str, object] | None],
) -> str | None:
    return _codex_browser_approval_decision(
        args=args,
        event_name=state.event_name,
        policy_action=state.policy_action,
        response_payload=state.response_payload,
        store=store,
        config=config,
        browser_wait_bound=state.browser_approval_wait_bound,
        daemon_client=state.browser_approval_daemon_client,
        expected_artifact_hash=state.runtime_artifact_hash,
        fresh_context_provider=fresh_context_provider,
    )


def finalize_native_artifact_hook(
    state: NativeArtifactHookState,
    args: argparse.Namespace,
    *,
    config: GuardConfig,
    output_stream: TextIO | None = None,
    payload: Mapping[str, object],
    store: GuardStore,
    post_wait_revalidator: Callable[[], NativeArtifactHookState | None] | None = None,
) -> int:
    action_envelope = state.action_envelope
    event_name = state.event_name
    policy_action = state.policy_action
    response_payload = state.response_payload
    runtime_artifact = state.runtime_artifact
    if _should_emit_copilot_hook_response(args):
        record_native_artifact_hook_receipt(state, store)
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
    fresh_state: NativeArtifactHookState | None = None

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

    codex_browser_decision = _browser_approval_decision(
        state,
        args,
        config=config,
        store=store,
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
        set_native_artifact_hook_final_action(
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
        record_native_artifact_hook_receipt(state, store)
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
        set_native_artifact_hook_final_action(
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
    record_native_artifact_hook_receipt(state, store)
    approval_context = live_hook_approval_context(response_payload, harness=args.harness, guard_home=store.guard_home)
    raw_runtime_reason = _runtime_artifact_native_reason(runtime_artifact, response_payload)
    if _should_emit_native_hook_exit_block(args, event_name=event_name, policy_action=policy_action):
        if _canonical_harness_name(args.harness) == "codex" and approval_context is not None:
            native_block_reason = _native_hook_reason(
                raw_runtime_reason,
                approval_context,
                _embedded_script_remediation(state),
            )
        else:
            native_block_reason = _native_hook_reason_for_harness(
                args.harness,
                raw_runtime_reason,
                approval_context,
                _embedded_script_remediation(state),
            )
        if _canonical_harness_name(args.harness) in {"kimi", "hermes"}:
            _emit_native_hook_response(
                harness=args.harness,
                policy_action=policy_action,
                event_name=event_name,
                reason=native_block_reason,
                output_stream=output_stream,
            )
        elif _canonical_harness_name(args.harness) == "grok":
            from ..adapters.grok_hooks import emit_grok_hook_response, grok_hook_process_exit
            emit_grok_hook_response(
                policy_action=policy_action, event_name=event_name,
                reason=native_block_reason, approval_payload=response_payload,
                output_stream=output_stream,
            )
            return grok_hook_process_exit(policy_action)
        elif _canonical_harness_name(args.harness) in {"pi", "omp"}:
            from ..adapters.pi_hooks import emit_pi_hook_response

            emit_pi_hook_response(
                policy_action=policy_action,
                reason=native_block_reason,
                approval_payload=response_payload,
                output_stream=output_stream,
            )
        elif _canonical_harness_name(args.harness) == "zcode":
            from ..adapters.zcode_hooks import emit_zcode_hook_response, zcode_hook_process_exit

            emit_zcode_hook_response(
                policy_action=policy_action,
                reason=native_block_reason,
                event_name=event_name,
                payload=payload,
                output_stream=output_stream,
            )
        elif _canonical_harness_name(args.harness) == "devin":
            from ..adapters.devin_hooks import emit_devin_hook_response

            emit_devin_hook_response(
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
            _embedded_script_remediation(state),
        )
    else:
        runtime_reason = _native_hook_reason_for_harness(
            args.harness,
            raw_runtime_reason,
            approval_context,
            _embedded_script_remediation(state),
        )
    if _should_emit_claude_native_pretooluse_notice(
        args,
        event_name=event_name,
        policy_action=policy_action,
    ):
        _emit_native_hook_notification_stderr(
            _claude_native_pretooluse_terminal_notice(payload=dict(payload), reason=runtime_reason)
        )
    canonical_harness = _canonical_harness_name(args.harness)
    system_message = None
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
    if getattr(args, "json", False) and output_stream is None:
        emit_reason = runtime_reason
        if canonical_harness == "copilot":
            emit_reason = _copilot_hook_reason(
                response_payload.get("why_now"),
                response_payload.get("review_hint"),
                response_payload.get("risk_headline"),
            )
        json_result = _native_hook_json_document(
            args,
            event_name=event_name,
            policy_action=policy_action,
            reason=emit_reason,
            envelope=response_payload,
            system_message=system_message,
            native_protocol_payload="hook_event_name" in payload or "event" not in payload,
            command_surface=action_envelope is not None and action_envelope.action_type == "shell_command",
            replayed_decision=isinstance(payload.get("policy_action"), str)
            and any(
                isinstance(payload.get(key), str) and payload.get(key)
                for key in ("artifact_id", "artifact_name", "tool_call_id")
            ),
            envelope_keyed="hook_event_name" in payload or "event" in payload,
            fail_closed_native_floor=(
                runtime_artifact is not None
                and _runtime_artifact_fail_closed_floor(runtime_artifact)
            ),
        )
        if json_result is not None:
            json_doc, json_rc = json_result
            if json_doc:
                _emit_native_hook_json_document(
                    json_doc,
                    compact=canonical_harness == "copilot",
                    output_stream=output_stream,
                )
            _record_harness_usage_for_hook(
                store=store,
                action_envelope=action_envelope,
                payload=payload,
                policy_action=policy_action,
            )
            return json_rc
    if _should_emit_native_hook_response(args) or _should_emit_native_hook_json_response(
        args,
        event_name=event_name,
        output_stream=output_stream,
    ):
        if canonical_harness == "grok":
            from ..adapters.grok_hooks import emit_grok_hook_response, grok_hook_process_exit

            emit_grok_hook_response(
                policy_action=policy_action, event_name=event_name,
                reason=runtime_reason, approval_payload=response_payload,
                output_stream=output_stream,
            )
            _record_harness_usage_for_hook(
                store=store,
                action_envelope=action_envelope,
                payload=payload,
                policy_action=policy_action,
            )
            return grok_hook_process_exit(policy_action)
        if canonical_harness in {"pi", "omp"}:
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
        if canonical_harness == "zcode":
            from ..adapters.zcode_hooks import emit_zcode_hook_response, zcode_hook_process_exit

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
            return zcode_hook_process_exit(policy_action=policy_action, event_name=event_name)
        if canonical_harness == "devin":
            from ..adapters.devin_hooks import emit_devin_hook_response

            emit_devin_hook_response(
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
    if event_name == "PostToolUse":
        # PostToolUse can never pause the tool (it already ran): the emitted
        # surface always continues the session. Codex reads the native block
        # envelope for hard stops; everything else keeps the machine envelope.
        _emit_native_post_tool_envelope(
            args.harness,
            policy_action=policy_action,
            reason=runtime_reason,
            response_payload=response_payload,
            output_stream=output_stream,
            as_json=getattr(args, "json", False),
        )
        _record_harness_usage_for_hook(
            store=store,
            action_envelope=action_envelope,
            payload=payload,
            policy_action=policy_action,
        )
        # A flagged outcome still exits nonzero: the machine envelope carries
        # the pending re-approval or masked-output evidence consumers expect
        # a failing rc for.
        return 1 if policy_action in {"review", "require-reapproval", "sandbox-required", "block"} else 0
    response_payload["continue"] = True
    response_payload["decision"] = (
        "block" if policy_action in {"review", "require-reapproval", "sandbox-required", "block"} else "allow"
    )
    _emit("hook", response_payload, getattr(args, "json", False))
    _record_harness_usage_for_hook(
        store=store,
        action_envelope=action_envelope,
        payload=payload,
        policy_action=policy_action,
    )
    if isinstance(payload.get("artifact_id"), str) and isinstance(payload.get("policy_action"), str):
        # The caller replayed a decision that was already recorded upstream;
        # the envelope acknowledges it without re-blocking the harness.
        return 0
    return 1 if policy_action in {"review", "require-reapproval", "sandbox-required", "block"} else 0

__all__ = [
    "finalize_native_artifact_hook",
]
