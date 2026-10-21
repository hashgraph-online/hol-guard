"""Native hook presentation pipeline driven by the Rust edge decision.

The Rust edge supplies the request-time floor and the resident supplies the
route (which handlers answer a prepared hook, in what order); this module
performs the mechanical composition and presentation that remain Python-owned:
payload normalization, harness state preparation, and the artifact flow, with
the cursor/copilot/claude control-plane bridges in the route handlers, approval
queueing, receipt persistence, and per-harness emission.
"""

# ruff: noqa: F403, F405

from __future__ import annotations

from collections.abc import Mapping
from time import monotonic as _monotonic
from typing import TYPE_CHECKING

from ..daemon.hook_request_parsing import runtime_hook_event_name
from ..daemon.runtime_hook_deadline import RuntimeHookDeadline
from ..native_hook_artifact_compose import NativeHookComposeError
from ..native_hook_artifact_facts import HookArtifactFactsUnavailableError
from ..native_hook_decision import NativeHookDecisionError
from ..native_hook_route import native_hook_route
from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..runtime.extension_control_runtime import (
    ExtensionControlRuntimeSnapshot,
    use_extension_control_snapshot,
)

if TYPE_CHECKING:
    from ..daemon.hook_worker import HookWorker

from ._commands_shared import *
from .commands_hook_native_availability import _emit_native_unavailable
from .commands_hook_native_compat import handle_native_cursor_post_tool, prepare_native_hook_payload
from .commands_hook_native_eval import evaluate_native_artifact_hook
from .commands_hook_native_finish import finalize_native_artifact_hook
from .commands_hook_native_prepare import prepare_native_hook_state
from .commands_hook_native_review import review_native_artifact_hook
from .commands_hook_native_route import (
    NativeHandler,
    NativeHookRun,
    hook_route_inputs,
    route_budget_seconds,
    run_route_plan,
)
from .commands_hook_native_route_handlers import HANDLERS
from .commands_hook_native_state import NativeArtifactHookState
from .commands_parser_helpers import *
from .commands_support import *
from .commands_support_connect import _synced_policy_payload
from .commands_support_hook_payload import _hook_action_envelope, _normalize_hook_payload
from .commands_support_runtime_artifacts import _hook_runtime_artifact, _runtime_data_flow_naming
from .commands_support_runtime_policy import _runtime_action_data_flow_signals
from .commands_support_runtime_resolution import (
    _copilot_hook_stage,
    _copilot_runtime_tool_call,
    _managed_install_for,
    _resolve_copilot_workspace_root,
)
from .commands_support_workspace import _workspace_from_hook_payload


def _artifact_flow(run: NativeHookRun) -> int | None:
    if run.runtime_artifact is None:
        return None
    try:
        return _run_native_artifact_hook_flow(
            run.args,
            action_envelope=run.action_envelope,
            config=run.config,
            context=run.context,
            data_flow_signals=run.data_flow_signals,
            payload=run.payload,
            runtime_artifact=run.runtime_artifact,
            runtime_workspace=run.runtime_workspace,
            store=run.store,
            managed_install=run.managed_install,
            output_stream=run.output_stream,
            workspace=run.runtime_workspace,
            native_edge_result=run.edge_mapping("result"),
            native_edge_receipt=run.edge_mapping("receipt"),
            native_recording_only=run.recording_only,
            _claimed_saved_allow_hash=run.claimed_saved_allow_hash,
            _claimed_trusted_request_override=run.claimed_trusted_request_override,
            _claimed_approval_request_id=run.claimed_approval_request_id,
            _claim_saved_approval=run.claim_saved_approval,
        )
    except HookArtifactFactsUnavailableError:
        # The resident owns these facts, so an outage is a host outage.
        return run.unavailable(HookArtifactFactsUnavailableError.code)
    except (NativeHookComposeError, NativeHookDecisionError) as error:
        # No resident directive or composition means no rendered verdict:
        # the outage shape.
        return run.unavailable(error.code)


# The fixed table the resident's route indexes: every handler a plan may name.
_HANDLERS: Mapping[str, NativeHandler] = {**HANDLERS, "artifact_flow": _artifact_flow}


def run_native_hook_pipeline(
    args: argparse.Namespace,
    *,
    config: GuardConfig | None,
    context: HarnessContext,
    payload: dict[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
    worker: HookWorker,
    output_stream: TextIO | None = None,
    _claim_saved_approval: bool = True,
    _claimed_saved_allow_hash: str | None = None,
    _claimed_trusted_request_override: bool = False,
    _claimed_approval_request_id: str | None = None,
) -> int:
    """Prepare the hook, ask the resident which handlers answer it, and run them."""

    invoked_event = runtime_hook_event_name(payload)
    # Anchor any harness-stamped hint at CLI entry, before state preparation.
    entry_clock = _monotonic()
    edge_timing = RuntimeHookDeadline.cli_edge_kwargs(payload)
    if config is None:
        # Native-mode hooks defer config reads until after the payload loads;
        # composition needs the same synced overlay the daemon applies.
        config = overlay_synced_guard_policy(
            load_guard_config(context.guard_home, workspace=runtime_workspace),
            _synced_policy_payload(store),
        )
    payload = _normalize_hook_payload(payload, harness=args.harness)
    (
        payload,
        managed_install,
        workspace_was_explicit,
        runtime_workspace,
        cursor_result,
        action_envelope,
        copilot_hook_stage,
        copilot_runtime_tool_call,
    ) = prepare_native_hook_state(
        args,
        payload=payload,
        context=context,
        store=store,
        workspace=runtime_workspace,
        prepare_native_hook_payload=prepare_native_hook_payload,
        managed_install_for=_managed_install_for,
        workspace_from_hook_payload=_workspace_from_hook_payload,
        handle_native_cursor_post_tool=handle_native_cursor_post_tool,
        resolve_copilot_workspace_root=_resolve_copilot_workspace_root,
        action_envelope_for=lambda **kwargs: _hook_action_envelope(guard_home=context.guard_home, **kwargs),
        copilot_hook_stage_for=_copilot_hook_stage,
        copilot_runtime_tool_call_for=_copilot_runtime_tool_call,
        config=config,
    )
    if cursor_result is not None:
        return cursor_result
    inputs = hook_route_inputs(
        args,
        payload,
        invoked_event=invoked_event,
        copilot_stage=copilot_hook_stage,
        copilot_tool_call_present=copilot_runtime_tool_call is not None,
    )
    try:
        route = native_hook_route(
            inputs,
            guard_home=context.guard_home,
            budget_seconds=route_budget_seconds(edge_timing, started_at=entry_clock),
        )
    except NativeHookDecisionError as error:
        # No route means no handler to run: the host outage response, never a guess.
        return _emit_native_unavailable(
            args,
            payload=payload,
            workspace=runtime_workspace,
            context=context,
            event_name=str(inputs["hook_event"] or inputs["runtime_event"]),
            reason_code=error.code,
            worker=worker,
            recording_only=False,
        )
    return run_route_plan(
        NativeHookRun(
            args=args,
            config=config,
            context=context,
            payload=payload,
            runtime_workspace=runtime_workspace,
            store=store,
            worker=worker,
            output_stream=output_stream,
            managed_install=managed_install,
            workspace_was_explicit=workspace_was_explicit,
            action_envelope=action_envelope,
            copilot_runtime_tool_call=copilot_runtime_tool_call,
            edge_timing=edge_timing,
            claim_saved_approval=_claim_saved_approval,
            claimed_saved_allow_hash=_claimed_saved_allow_hash,
            claimed_trusted_request_override=_claimed_trusted_request_override,
            claimed_approval_request_id=_claimed_approval_request_id,
            event_name=route.event_name,
        ),
        route.plan,
        _HANDLERS,
    )


def _fresh_native_artifact_evaluation(
    args: argparse.Namespace,
    *,
    context: HarnessContext,
    payload: dict[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
    claim_saved_approval: bool,
    claimed_saved_allow_hash: str | None = None,
    claimed_trusted_request_override: bool = False,
    claimed_package_approval_consumed: bool = False,
    claimed_approval_request_id: str | None = None,
    trusted_request_override_hash: str | None = None,
    post_claim_revalidator=None,
    native_edge_result: Mapping[str, object] | None = None,
    native_edge_receipt: Mapping[str, object] | None = None,
    native_recording_only: bool = False,
):
    fresh_config = overlay_synced_guard_policy(
        load_guard_config(context.guard_home, workspace=runtime_workspace),
        _synced_policy_payload(store),
    )
    fresh_action_envelope = _hook_action_envelope(
        harness=args.harness,
        payload=payload,
        home_dir=context.home_dir,
        workspace=runtime_workspace,
        guard_home=context.guard_home,
    )
    fresh_data_flow_signals, fresh_data_flow_artifact = _runtime_action_data_flow_signals(
        fresh_action_envelope,
        workspace=runtime_workspace,
        guard_home=context.guard_home,
        naming=_runtime_data_flow_naming(
            harness=args.harness,
            payload=payload,
            action_envelope=fresh_action_envelope,
            home_dir=context.home_dir,
            workspace=runtime_workspace,
        ),
    )
    fresh_snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    )
    with use_extension_control_snapshot(fresh_snapshot):
        fresh_runtime_artifact = _hook_runtime_artifact(
            harness=args.harness,
            payload=payload,
            action_envelope=fresh_action_envelope,
            data_flow_signals=fresh_data_flow_signals,
            data_flow_artifact=fresh_data_flow_artifact,
            home_dir=context.home_dir,
            guard_home=context.guard_home,
            workspace=runtime_workspace,
        )
    if fresh_runtime_artifact is None:
        return None
    return evaluate_native_artifact_hook(
        args,
        action_envelope=fresh_action_envelope,
        config=fresh_config,
        context=context,
        data_flow_signals=fresh_data_flow_signals,
        guard_home=context.guard_home,
        payload=payload,
        runtime_artifact=fresh_runtime_artifact,
        runtime_workspace=runtime_workspace,
        store=store,
        trusted_request_override_hash=trusted_request_override_hash,
        post_claim_revalidator=post_claim_revalidator if claimed_saved_allow_hash is None else None,
        _claimed_saved_allow_hash=claimed_saved_allow_hash,
        _claimed_trusted_request_override=claimed_trusted_request_override,
        _claimed_package_approval_consumed=claimed_package_approval_consumed,
        _claimed_approval_request_id=claimed_approval_request_id,
        _claim_saved_approval=claimed_saved_allow_hash is None and claim_saved_approval,
        native_edge_result=native_edge_result,
        native_edge_receipt=native_edge_receipt,
        native_recording_only=native_recording_only,
    )


def _run_native_artifact_hook_flow(
    args: argparse.Namespace,
    *,
    action_envelope,
    config: GuardConfig,
    context: HarnessContext,
    data_flow_signals,
    managed_install,
    output_stream: TextIO | None,
    payload: dict[str, object],
    runtime_artifact,
    runtime_workspace: Path | None,
    store: GuardStore,
    workspace: Path | None,
    native_edge_result: Mapping[str, object] | None,
    native_edge_receipt: Mapping[str, object] | None,
    native_recording_only: bool,
    _claimed_saved_allow_hash: str | None,
    _claimed_trusted_request_override: bool,
    _claimed_approval_request_id: str | None,
    _claim_saved_approval: bool,
) -> int:
    def revalidate_runtime_after_claim(claimed_hash, trusted_override, approval_request_id, package_consumed):
        return _fresh_native_artifact_evaluation(
            args,
            context=context,
            payload=payload,
            runtime_workspace=runtime_workspace,
            store=store,
            claim_saved_approval=_claim_saved_approval,
            claimed_saved_allow_hash=claimed_hash,
            claimed_trusted_request_override=trusted_override,
            claimed_package_approval_consumed=package_consumed,
            claimed_approval_request_id=approval_request_id,
            post_claim_revalidator=revalidate_runtime_after_claim,
            native_edge_result=native_edge_result,
            native_edge_receipt=native_edge_receipt,
            native_recording_only=native_recording_only,
        )

    evaluated = evaluate_native_artifact_hook(
        args,
        action_envelope=action_envelope,
        config=config,
        context=context,
        data_flow_signals=data_flow_signals,
        guard_home=context.guard_home,
        payload=payload,
        runtime_artifact=runtime_artifact,
        runtime_workspace=runtime_workspace,
        store=store,
        post_claim_revalidator=revalidate_runtime_after_claim,
        _claimed_saved_allow_hash=_claimed_saved_allow_hash,
        _claimed_trusted_request_override=_claimed_trusted_request_override,
        _claimed_approval_request_id=_claimed_approval_request_id,
        _claim_saved_approval=_claim_saved_approval,
        native_edge_result=native_edge_result,
        native_edge_receipt=native_edge_receipt,
        native_recording_only=native_recording_only,
    )
    if isinstance(evaluated, int):
        return evaluated
    result = review_native_artifact_hook(
        evaluated,
        args,
        config=config,
        context=context,
        guard_home=context.guard_home,
        managed_install=managed_install,
        output_stream=output_stream,
        payload=payload,
        store=store,
        workspace=workspace,
    )
    if result is not None:
        return result

    def revalidate_runtime_after_wait() -> NativeArtifactHookState | None:
        fresh = _fresh_native_artifact_evaluation(
            args,
            context=context,
            payload=payload,
            runtime_workspace=runtime_workspace,
            store=store,
            claim_saved_approval=_claim_saved_approval,
            trusted_request_override_hash=evaluated.runtime_artifact_hash,
            native_edge_result=native_edge_result,
            native_edge_receipt=native_edge_receipt,
            native_recording_only=native_recording_only,
        )
        return fresh if isinstance(fresh, NativeArtifactHookState) else None

    return finalize_native_artifact_hook(
        evaluated,
        args,
        config=config,
        output_stream=output_stream,
        payload=payload,
        store=store,
        post_wait_revalidator=revalidate_runtime_after_wait,
    )


__all__ = [
    "run_native_hook_pipeline",
]
