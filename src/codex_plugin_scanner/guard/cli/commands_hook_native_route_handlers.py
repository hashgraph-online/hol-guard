"""The handlers a native hook route can name.

Each handler runs the effects of one control-plane bridge and either answers
with an exit code or declines with ``None`` so the next planned handler runs.
A handler decides only what its own effects reveal (whether containment took
the call, whether Copilot resolved a tool call, whether a runtime artifact was
found); which handlers run, and in what order, is the resident route's call.
The artifact flow handler lives beside the artifact flow in the pipeline module.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from ..config import load_guard_config, overlay_synced_guard_policy
from ..native_hook_decision import _INVALID, NativeHookDecisionError
from ..native_hook_route import PASSTHROUGH_HANDLER
from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..runtime.extension_control_runtime import (
    ExtensionControlRuntimeSnapshot,
    use_extension_control_snapshot,
)
from ._commands_shared import _now
from .commands_hook_native_claude import (
    run_native_claude_permission_prompt_notification,
    run_native_claude_permission_request,
)
from .commands_hook_native_containment import emit_native_containment_route
from .commands_hook_native_copilot import (
    run_native_copilot_permission_request,
    run_native_copilot_pretool,
)
from .commands_hook_native_generic import run_native_generic_payload as _run_native_generic_payload
from .commands_hook_native_route import NativeHandler, NativeHookRun
from .commands_support_claude_approval import (
    _claude_guard_question_verdict,
    _persist_claude_guard_question_decision,
)
from .commands_support_connect import _synced_policy_payload
from .commands_support_hook_payload import _hook_action_envelope
from .commands_support_hook_state import _load_single_claude_pending_permission
from .commands_support_permission_store import _discard_claude_pending_permissions
from .commands_support_runtime_artifacts import _hook_runtime_artifact, _runtime_data_flow_naming
from .commands_support_runtime_policy import _runtime_action_data_flow_signals
from .commands_support_runtime_resolution import _copilot_runtime_tool_call

if TYPE_CHECKING:
    from ..config import GuardConfig


def _fresh_config(run: NativeHookRun) -> GuardConfig:
    return overlay_synced_guard_policy(
        load_guard_config(run.context.guard_home, workspace=run.runtime_workspace),
        _synced_policy_payload(run.store),
    )


def _preferred_workspace_config(run: NativeHookRun) -> str:
    return "ide" if run.workspace_was_explicit else "cli"


def _fresh_copilot_tool_call_authority(run: NativeHookRun):
    def authority():
        fresh_config = _fresh_config(run)
        fresh_tool_call = _copilot_runtime_tool_call(
            payload=run.payload,
            home_dir=run.context.home_dir,
            workspace=run.runtime_workspace,
            config=fresh_config,
            preferred_workspace_config=_preferred_workspace_config(run),
        )
        if fresh_tool_call is None:
            return None
        fresh_artifact, fresh_artifact_hash, fresh_arguments = fresh_tool_call
        return fresh_config, fresh_artifact, fresh_artifact_hash, fresh_arguments

    return authority


def passthrough(run: NativeHookRun) -> int:
    # Empty output and exit 0 carry no decision, so the harness shows its own
    # approval prompt instead of reading a review as a refusal.
    return 0


def claude_guard_question(run: NativeHookRun) -> int | None:
    pending_pair = _load_single_claude_pending_permission(run.store, run.payload)
    if pending_pair is None:
        return None
    verdict = _claude_guard_question_verdict(run.payload, pending_pair[1])
    if not verdict.is_question:
        return None
    try:
        _persist_claude_guard_question_decision(run.store, run.payload, pending_pair=pending_pair, verdict=verdict)
    except NativeHookDecisionError as error:
        # The resident decides what is saved; without its answer nothing is
        # persisted and the host gets the same outage shape as everywhere else.
        return run.unavailable(error.code)
    return 0


def native_edge(run: NativeHookRun) -> int | None:
    run.edge = run.worker.review_native_edge_decision(
        payload=run.payload,
        harness=run.args.harness,
        default_harness=run.args.harness,
        home_dir=run.context.home_dir,
        guard_home=run.context.guard_home,
        workspace=run.runtime_workspace,
        **run.edge_timing,
    )
    return None


def edge_unavailable(run: NativeHookRun) -> int | None:
    if run.edge_field("result") is not None:
        return None
    return run.unavailable(str(run.edge_field("failure_reason_code") or "native_hook_event_unavailable"))


def containment(run: NativeHookRun) -> int | None:
    return emit_native_containment_route(
        run.edge, run.payload, run.context, run.runtime_workspace, run.output_stream, run.store
    )


def copilot_pretool(run: NativeHookRun) -> int | None:
    tool_call = run.copilot_runtime_tool_call
    if tool_call is None:
        # The route named this handler for a tool call that is not there.
        return run.unavailable(_INVALID)
    try:
        return run_native_copilot_pretool(
            run.args,
            action_envelope=run.action_envelope,
            config=run.config,
            context=run.context,
            copilot_runtime_tool_call=tool_call,
            output_stream=run.output_stream,
            payload=run.payload,
            runtime_workspace=run.runtime_workspace,
            store=run.store,
            fresh_tool_call_authority_provider=_fresh_copilot_tool_call_authority(run),
            native_edge_result=run.edge_mapping("result"),
        )
    except NativeHookDecisionError as error:
        # Same outage shape as the generic path, keeping the resident's reason code.
        return run.unavailable(error.code)


def copilot_permission_request(run: NativeHookRun) -> int | None:
    try:
        return run_native_copilot_permission_request(
            run.args,
            action_envelope=run.action_envelope,
            config=run.config,
            context=run.context,
            copilot_permission_request=_copilot_runtime_tool_call(
                payload=run.payload,
                home_dir=run.context.home_dir,
                workspace=run.runtime_workspace,
                config=run.config,
                preferred_workspace_config=_preferred_workspace_config(run),
            ),
            guard_home=run.context.guard_home,
            managed_install=run.managed_install,
            output_stream=run.output_stream,
            payload=run.payload,
            runtime_workspace=run.runtime_workspace,
            store=run.store,
            fresh_tool_call_authority_provider=_fresh_copilot_tool_call_authority(run),
        )
    except NativeHookDecisionError as error:
        return run.unavailable(error.code)


def runtime_artifact(run: NativeHookRun) -> int | None:
    signals, data_flow_artifact = _runtime_action_data_flow_signals(
        run.action_envelope,
        workspace=run.runtime_workspace,
        guard_home=run.context.guard_home,
        naming=_runtime_data_flow_naming(
            harness=run.args.harness,
            payload=run.payload,
            action_envelope=run.action_envelope,
            home_dir=run.context.home_dir,
            workspace=run.runtime_workspace,
        ),
    )
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        run.store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    )
    with use_extension_control_snapshot(snapshot):
        run.runtime_artifact = _hook_runtime_artifact(
            harness=run.args.harness,
            payload=run.payload,
            action_envelope=run.action_envelope,
            data_flow_signals=signals,
            data_flow_artifact=data_flow_artifact,
            home_dir=run.context.home_dir,
            guard_home=run.context.guard_home,
            workspace=run.runtime_workspace,
        )
    run.data_flow_signals = signals
    return None


def claude_permission_request(run: NativeHookRun) -> int | None:
    return run_native_claude_permission_request(
        run.args,
        config=run.config,
        output_stream=run.output_stream,
        payload=run.payload,
        runtime_artifact=run.runtime_artifact,
        runtime_workspace=run.runtime_workspace,
        store=run.store,
    )


def claude_permission_prompt(run: NativeHookRun) -> int | None:
    return run_native_claude_permission_prompt_notification(
        run.args,
        output_stream=run.output_stream,
        payload=run.payload,
        store=run.store,
    )


def claude_stop(run: NativeHookRun) -> int | None:
    discarded = _discard_claude_pending_permissions(run.store, run.payload)
    run.store.add_event(
        "claude/turn_stop",
        {
            "session_id": run.payload.get("session_id"),
            "discarded_pending_permissions": discarded,
        },
        _now(),
    )
    return 0


def generic_flow(run: NativeHookRun) -> int | None:
    def run_generic(*generic_args, **generic_kwargs) -> int:
        # No resident decision means no verdict: answer with the host outage shape.
        try:
            return _run_native_generic_payload(*generic_args, **generic_kwargs)
        except NativeHookDecisionError as error:
            return run.unavailable(error.code)

    def revalidate_generic_after_claim(claimed_artifact_hash: str, claimed_approval: Mapping[str, object]) -> int:
        fresh_config = _fresh_config(run)
        fresh_action_envelope = _hook_action_envelope(
            harness=run.args.harness,
            payload=run.payload,
            home_dir=run.context.home_dir,
            workspace=run.runtime_workspace,
            guard_home=run.context.guard_home,
        )
        return run_generic(
            run.args,
            action_envelope=fresh_action_envelope,
            config=fresh_config,
            home_dir=run.context.home_dir,
            output_stream=run.output_stream,
            payload=run.payload,
            runtime_artifact_checked=True,
            runtime_workspace=run.runtime_workspace,
            store=run.store,
            native_edge_result=run.edge_mapping("result"),
            native_edge_receipt=run.edge_mapping("receipt"),
            _claimed_saved_allow_hash=claimed_artifact_hash,
            _claimed_saved_approval=claimed_approval,
            _claim_saved_approval=False,
        )

    return run_generic(
        run.args,
        action_envelope=run.action_envelope,
        config=run.config,
        home_dir=run.context.home_dir,
        output_stream=run.output_stream,
        payload=run.payload,
        runtime_artifact_checked=True,
        runtime_workspace=run.runtime_workspace,
        store=run.store,
        post_claim_revalidator=revalidate_generic_after_claim,
        native_edge_result=run.edge_mapping("result"),
        native_edge_receipt=run.edge_mapping("receipt"),
        _claimed_saved_allow_hash=run.claimed_saved_allow_hash,
        _claim_saved_approval=run.claim_saved_approval,
    )


# The route names a handler by these keys; ``artifact_flow`` is added by the
# pipeline module, which owns the artifact flow it runs.
HANDLERS: Mapping[str, NativeHandler] = {
    PASSTHROUGH_HANDLER: passthrough,
    "claude_guard_question": claude_guard_question,
    "native_edge": native_edge,
    "edge_unavailable": edge_unavailable,
    "containment": containment,
    "copilot_pretool": copilot_pretool,
    "copilot_permission_request": copilot_permission_request,
    "runtime_artifact": runtime_artifact,
    "claude_permission_request": claude_permission_request,
    "claude_permission_prompt": claude_permission_prompt,
    "claude_stop": claude_stop,
    "generic_flow": generic_flow,
}

__all__ = ["HANDLERS"]
