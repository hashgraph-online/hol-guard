"""Guard CLI runtime artifact hook review flow.

The resident routes a reviewed artifact verdict (``artifact_review_route``):
silent denial, observe record, Copilot or Claude native answer, approval-center
queue, or none. This module gathers the facts that route is decided from, asks,
and executes the answer. It holds no branch of its own: a route the resident
cannot give raises, and the hook's fail-closed handling answers instead.
"""

# ruff: noqa: F403, F405

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, cast

from .commands_support import *

if TYPE_CHECKING:
    from .commands_support_claude_approval import _claude_native_pretooluse_terminal_notice
    from .commands_support_hook_payload import _emit_native_hook_notification_stderr, _emit_native_hook_response
    from .commands_support_hook_state import _record_claude_permission_notice
    from .commands_support_interaction import _record_harness_usage_for_hook
    from .commands_support_prompts import (
        _claude_prompt_briefing,
        _copilot_hook_reason,
        _emit_copilot_hook_response,
        _prompt_request_classes,
        _prompt_requires_hard_block,
        _runtime_artifact_native_reason,
    )
    from .commands_support_runtime_policy import _terminalize_runtime_action_copy
    from .commands_support_runtime_resolution import _canonical_harness_name


from ..blocked_request_mode import asks_for_approval
from ..harness_posture import harness_is_recording_only
from ..models import GuardAction
from ..native_hook_artifact_compose import native_hook_compose
from ..native_hook_decision import native_artifact_review_route
from ._commands_shared import *
from .commands_hook_native_generic_render import directive_system_message
from .commands_hook_native_review_queue import queue_native_approval
from .commands_hook_native_silent_review import apply_unprompted_native_review
from .commands_hook_native_state import (
    NativeArtifactHookState,
    record_native_artifact_hook_receipt,
    set_native_artifact_hook_final_action,
)
from .commands_parser_helpers import *
from .commands_support_observe_queue import queue_observe_mode_request

_OBSERVE_EXECUTION_SOURCE_FIELDS = (
    "current_config_action",
    "current_action_override",
    "trusted_cli_override",
    "untrusted_hook_payload_hint",
    "package_action",
    "data_flow_action",
    "scanner_action",
)


def _observe_mode_executable_action(state: NativeArtifactHookState) -> GuardAction:
    """Ask the resident which composed sources still execute in observe mode.

    Python gathers the sources and sends them; which of them survive observe
    mode, and which one names the action, is the resident's answer. A call the
    resident cannot serve raises, and the hook's fail-closed handling turns it
    into an availability response rather than a recorded guess.
    """

    composition = state.response_payload.get("policy_composition")
    sources = composition if isinstance(composition, Mapping) else {}
    answer = native_hook_compose(
        "observe_executable_action",
        {
            **{key: sources.get(key) for key in _OBSERVE_EXECUTION_SOURCE_FIELDS},
            "package_evaluation_action": getattr(state.package_evaluation, "policy_action", None),
        },
        guard_home=state.guard_home,
    )
    return cast(GuardAction, answer["executable_action"])


_TERMINAL_REVIEW_HINT = (
    "HOL Guard blocked this action with a terminal policy decision. Browser approval cannot override it."
)


def _terminalize(response_payload: dict[str, object], policy_action: str, mode: str) -> None:
    """Mark a terminal verdict: no approval requests, no browser override."""

    response_payload["approval_requests"] = []
    response_payload["terminal_action"] = policy_action
    _terminalize_runtime_action_copy(response_payload)
    if mode == "observe":
        response_payload["observed_terminal_action"] = policy_action
        return
    response_payload["operation_status"] = "blocked"
    response_payload["terminal"] = True
    response_payload["review_hint"] = _TERMINAL_REVIEW_HINT


def _record_observed_review(
    state: NativeArtifactHookState,
    *,
    config: GuardConfig,
    store: GuardStore,
) -> None:
    """Record the verdict Watch mode observed and make the executable action final."""

    state.response_payload["approval_requests"] = []
    # The resident accepted this action when it routed the verdict.
    observed_policy_action = cast(GuardAction, state.policy_action)
    # One answer serves both the queued record and the final action:
    # the sources do not change between them, so asking twice would
    # only spend a second round trip on the same question.
    executable_action = _observe_mode_executable_action(state)
    queue_observe_mode_request(
        action_envelope=state.action_envelope,
        artifact=state.runtime_artifact,
        artifact_hash=state.runtime_artifact_hash,
        changed_fields=state.changed_capabilities,
        executable_action=executable_action,
        observed_policy_action=observed_policy_action,
        redaction_level=config.receipt_redaction_level,
        risk_summary=state.risk_summary,
        scanner_evidence=state.scanner_evidence_payload,
        store=store,
    )
    set_native_artifact_hook_final_action(
        state,
        executable_action,
        observed_policy_action=observed_policy_action,
    )
    state.browser_approval_daemon_client = None


def _review_route_facts(
    state: NativeArtifactHookState,
    args: argparse.Namespace,
    *,
    config: GuardConfig,
    output_stream: TextIO | None,
) -> dict[str, object]:
    """What the resident routes a reviewed verdict from."""

    artifact = state.runtime_artifact
    return {
        "harness": str(args.harness),
        "canonical_harness": _canonical_harness_name(args.harness),
        "event": state.event_name,
        "policy_action": state.policy_action,
        "artifact_type": artifact.artifact_type,
        "observe_mode": harness_is_recording_only(config, args.harness),
        "asks_for_approval": asks_for_approval(config),
        "json": bool(getattr(args, "json", False)),
        "output_stream_present": output_stream is not None,
        "prompt_hard_block": _prompt_requires_hard_block(artifact),
        "prompt_secret_read": "secret_read" in _prompt_request_classes(artifact),
    }


def _record_answered_hook(state: NativeArtifactHookState, store: GuardStore, payload: Mapping[str, object]) -> None:
    """Leave the receipt and usage record of a verdict the hook answered itself."""

    record_native_artifact_hook_receipt(state, store)
    _record_harness_usage_for_hook(
        store=store,
        action_envelope=state.action_envelope,
        payload=payload,
        policy_action=state.policy_action,
    )


def _emit_claude_response(
    state: NativeArtifactHookState,
    args: argparse.Namespace,
    route: Mapping[str, object],
    *,
    native_reason: Callable[[], str],
    output_stream: TextIO | None,
    payload: Mapping[str, object],
) -> None:
    """Answer Claude natively with the messages the route names."""

    if route["record_claude_notice"]:
        _emit_native_hook_notification_stderr(
            _claude_native_pretooluse_terminal_notice(payload=dict(payload), reason=native_reason())
        )
    policy_action = state.policy_action
    additional_context = route["additional_context"]
    _emit_native_hook_response(
        harness=args.harness,
        policy_action=policy_action,
        event_name=state.event_name,
        reason=native_reason(),
        system_message=directive_system_message(route, policy_action=policy_action, reason=native_reason),
        additional_context=(
            None
            if additional_context == "none"
            else _claude_prompt_briefing(native_reason(), secret=additional_context == "claude_prompt_secret")
        ),
        output_stream=output_stream,
    )


def review_native_artifact_hook(
    state: NativeArtifactHookState,
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
    """Execute the resident's route for the reviewed artifact verdict.

    Returns the hook's exit code when the route answered the harness itself,
    and ``None`` when the hook continues to its final response.
    """

    route = native_artifact_review_route(
        _review_route_facts(state, args, config=config, output_stream=output_stream),
        guard_home=state.guard_home,
    )
    kind = route["route"]
    if kind in {"silent_review", "silent_block"}:
        apply_unprompted_native_review(state, args, store, config, route)
        return None
    policy_action = state.policy_action
    response_payload = state.response_payload
    if route["terminalize"] != "none":
        _terminalize(response_payload, policy_action, str(route["terminalize"]))
    if kind == "observe":
        _record_observed_review(state, config=config, store=store)
        return None
    reasons: list[str] = []

    def native_reason() -> str:
        """The resident's reason, composed once and only where a branch shows it."""

        if not reasons:
            reasons.append(
                _runtime_artifact_native_reason(
                    state.runtime_artifact,
                    response_payload,
                    composer=native_hook_compose,
                    guard_home=state.guard_home,
                )
            )
        return reasons[0]

    if route["record_claude_notice"]:
        _record_claude_permission_notice(
            store=store,
            payload=dict(payload),
            reason=native_reason(),
            artifact=state.runtime_artifact,
            artifact_hash=state.runtime_artifact_hash,
        )
    if kind == "copilot_response":
        _record_answered_hook(state, store, payload)
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
    if kind == "native_response":
        _emit_claude_response(
            state,
            args,
            route,
            native_reason=native_reason,
            output_stream=output_stream,
            payload=payload,
        )
        _record_answered_hook(state, store, payload)
        return 0
    daemon_client: object | None = None
    wait_bound: bool | None = None
    if kind == "queue_approval":
        daemon_client, wait_bound = queue_native_approval(
            state,
            args,
            attach_cursor_request_ids=cast(bool, route["attach_cursor_request_ids"]),
            config=config,
            context=context,
            guard_home=guard_home,
            managed_install=managed_install,
            payload=payload,
            store=store,
            workspace=workspace,
        )
    state.browser_approval_daemon_client = daemon_client
    state.browser_approval_wait_bound = wait_bound
    return None


__all__ = [
    "review_native_artifact_hook",
]
