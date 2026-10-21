"""Guard CLI runtime artifact hook final response flow."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

from typing import TYPE_CHECKING


from ..native_hook_artifact_compose import native_hook_compose
from ..native_hook_decision import native_artifact_directive
from .commands_support import *

if TYPE_CHECKING:
    from .commands_support_hook_payload import _emit_native_hook_response
    from .commands_support_interaction import (
        _codex_browser_approval_decision,
        _record_harness_usage_for_hook,
        _should_emit_copilot_hook_response,
    )
    from .commands_support_prompts import (
        _copilot_hook_reason,
        _emit_copilot_hook_response,
        _runtime_artifact_native_reason,
    )
    from .commands_support_runtime_resolution import _canonical_harness_name


from ._commands_shared import *
from .commands_parser_helpers import *
from .commands_hook_native_generic_render import render_generic_hook
from .commands_support_prompts import _prompt_request_classes, _prompt_requires_hard_block

from .commands_hook_native_state import (
    NativeArtifactHookState,
    record_native_artifact_hook_receipt,
    set_native_artifact_hook_final_action,
)


def _embedded_script_remediation(state: NativeArtifactHookState) -> str | None:
    """Guidance when the command carries an inline script body.

    The resident's directive says whether a reason includes it.
    """

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
    approval_context = live_hook_approval_context(response_payload, harness=args.harness, guard_home=store.guard_home)
    canonical_harness = _canonical_harness_name(args.harness)
    is_claude = canonical_harness == "claude-code"
    directive = native_artifact_directive(
        {
            "harness": str(args.harness),
            "canonical_harness": canonical_harness,
            "event": event_name,
            "policy_action": policy_action,
            "json": bool(getattr(args, "json", False)),
            "output_stream_present": output_stream is not None,
            "replayed": isinstance(payload.get("artifact_id"), str) and isinstance(payload.get("policy_action"), str),
            "approval_context_present": approval_context is not None,
            "prompt_hard_block": is_claude and _prompt_requires_hard_block(runtime_artifact),
            "prompt_secret_read": is_claude and "secret_read" in _prompt_request_classes(runtime_artifact),
        },
        guard_home=store.guard_home,
    )
    # The receipt follows the directive: a resident that cannot say how to
    # answer leaves no record of a verdict the harness never received.
    record_native_artifact_hook_receipt(state, store)

    def raw_runtime_reason() -> str:
        """The resident's reason for this artifact.

        The renderer asks for it at most once, and only on a branch that shows
        a reason: a pass that shows none must neither pay for the round trip
        nor fail closed when the resident cannot serve one.
        """

        return _runtime_artifact_native_reason(
            runtime_artifact,
            response_payload,
            composer=native_hook_compose,
            guard_home=store.guard_home,
        )

    exit_code = render_generic_hook(
        args,
        action_envelope=action_envelope,
        approval_context=approval_context,
        canonical_harness=canonical_harness,
        command_text=None,
        directive=directive,
        envelope=response_payload,
        event_name=event_name,
        incoming_reason=None,
        native_edge_result=None,
        output_stream=output_stream,
        payload=dict(payload),
        policy_action=policy_action,
        remediation=lambda: _embedded_script_remediation(state),
        verified_benign=lambda: False,
        coalesce=lambda _incoming, reason: reason,
        artifact_reason=raw_runtime_reason,
    )
    _record_harness_usage_for_hook(
        store=store,
        action_envelope=action_envelope,
        payload=payload,
        policy_action=policy_action,
    )
    return exit_code


__all__ = [
    "finalize_native_artifact_hook",
]
