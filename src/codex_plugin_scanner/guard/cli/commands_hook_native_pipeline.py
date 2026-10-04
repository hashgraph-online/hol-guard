"""Native hook presentation pipeline driven by the Rust edge decision.

The Rust edge supplies the request-time floor; this module performs the
mechanical composition and presentation that remain Python-owned: payload
normalization, harness state preparation, cursor/copilot/claude control-plane
bridges, approval queueing, receipt persistence, and per-harness emission.
"""

# ruff: noqa: F403, F405

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from ..daemon.hook_request_parsing import runtime_hook_event_name
from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..runtime.extension_control_runtime import (
    ExtensionControlRuntimeSnapshot,
    use_extension_control_snapshot,
)

if TYPE_CHECKING:
    from ..daemon.hook_worker import HookWorker
    from ._commands_shared import _now

from ._commands_shared import *
from .commands_hook_native_availability import _emit_native_unavailable
from .commands_hook_native_claude import (
    run_native_claude_permission_prompt_notification,
    run_native_claude_permission_request,
)
from .commands_hook_native_compat import handle_native_cursor_post_tool, prepare_native_hook_payload
from .commands_hook_native_copilot import (
    run_native_copilot_permission_request,
    run_native_copilot_pretool,
)
from .commands_hook_native_eval import evaluate_native_artifact_hook
from .commands_hook_native_finish import finalize_native_artifact_hook
from .commands_hook_native_generic import run_native_generic_payload
from .commands_hook_native_prepare import prepare_native_hook_state
from .commands_hook_native_review import review_native_artifact_hook
from .commands_hook_native_state import NativeArtifactHookState
from .commands_parser_helpers import *
from .commands_support import *
from .commands_support_claude_approval import (
    _is_claude_guard_approval_question,
    _persist_claude_guard_question_decision,
)
from .commands_support_connect import _synced_policy_payload
from .commands_support_hook_payload import _hook_action_envelope, _normalize_hook_payload
from .commands_support_hook_state import _load_single_claude_pending_permission
from .commands_support_permission_store import _discard_claude_pending_permissions
from .commands_support_runtime_artifacts import _hook_event_name, _hook_runtime_artifact
from .commands_support_runtime_policy import _runtime_action_data_flow_signals
from .commands_support_runtime_resolution import (
    _canonical_harness_name,
    _copilot_hook_stage,
    _copilot_runtime_tool_call,
    _is_copilot_permission_request,
    _managed_install_for,
    _resolve_copilot_workspace_root,
)
from .commands_support_workspace import _workspace_from_hook_payload

_NATIVE_EDGE_EVENTS = frozenset({"PreToolUse", "PostToolUse", "UserPromptSubmit"})


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
    """Compose the native edge decision into the harness hook response."""

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
        action_envelope_for=_hook_action_envelope,
        copilot_hook_stage_for=_copilot_hook_stage,
        copilot_runtime_tool_call_for=_copilot_runtime_tool_call,
        config=config,
    )
    if cursor_result is not None:
        return cursor_result

    if _canonical_harness_name(args.harness) == "claude-code" and _hook_event_name(payload) == "PostToolUse":
        pending_pair = _load_single_claude_pending_permission(store, payload)
        if pending_pair is not None and _is_claude_guard_approval_question(payload, pending_pair[1]):
            _persist_claude_guard_question_decision(store, payload)
            return 0

    edge = worker.review_native_edge_decision(
        payload=payload,
        harness=args.harness,
        default_harness=args.harness,
        home_dir=context.home_dir,
        guard_home=context.guard_home,
        workspace=runtime_workspace,
    )
    edge_result = edge.get("result") if isinstance(edge, Mapping) else None
    edge_receipt = edge.get("receipt") if isinstance(edge, Mapping) else None
    edge_failure = edge.get("failure_reason_code") if isinstance(edge, Mapping) else None
    event_name = _hook_event_name(payload) or runtime_hook_event_name(payload)
    if event_name in _NATIVE_EDGE_EVENTS and edge_result is None:
        return _emit_native_unavailable(
            args,
            payload=payload,
            workspace=runtime_workspace,
            context=context,
            event_name=event_name,
            reason_code=str(edge_failure or "native_hook_event_unavailable"),
            worker=worker,
            recording_only=bool(edge.get("recording_only")) if isinstance(edge, Mapping) else False,
        )

    def fresh_copilot_tool_call_authority():
        fresh_config = overlay_synced_guard_policy(
            load_guard_config(context.guard_home, workspace=runtime_workspace),
            _synced_policy_payload(store),
        )
        fresh_tool_call = _copilot_runtime_tool_call(
            payload=payload,
            home_dir=context.home_dir,
            workspace=runtime_workspace,
            config=fresh_config,
            preferred_workspace_config="ide" if workspace_was_explicit else "cli",
        )
        if fresh_tool_call is None:
            return None
        fresh_artifact, fresh_artifact_hash, fresh_arguments = fresh_tool_call
        return fresh_config, fresh_artifact, fresh_artifact_hash, fresh_arguments

    result = run_native_copilot_pretool(
        args,
        action_envelope=action_envelope,
        config=config,
        context=context,
        copilot_hook_stage=copilot_hook_stage,
        copilot_runtime_tool_call=copilot_runtime_tool_call,
        output_stream=output_stream,
        payload=payload,
        runtime_workspace=runtime_workspace,
        store=store,
        fresh_tool_call_authority_provider=fresh_copilot_tool_call_authority,
        native_edge_result=edge_result if isinstance(edge_result, Mapping) else None,
    )
    if result is not None:
        return result
    copilot_permission_request = (
        _copilot_runtime_tool_call(
            payload=payload,
            home_dir=context.home_dir,
            workspace=runtime_workspace,
            config=config,
            preferred_workspace_config="ide" if workspace_was_explicit else "cli",
        )
        if args.harness == "copilot" and _is_copilot_permission_request(payload)
        else None
    )
    result = run_native_copilot_permission_request(
        args,
        action_envelope=action_envelope,
        config=config,
        context=context,
        copilot_permission_request=copilot_permission_request,
        guard_home=context.guard_home,
        managed_install=managed_install,
        output_stream=output_stream,
        payload=payload,
        runtime_workspace=runtime_workspace,
        store=store,
        fresh_tool_call_authority_provider=fresh_copilot_tool_call_authority,
    )
    if result is not None:
        return result
    data_flow_signals = _runtime_action_data_flow_signals(action_envelope, workspace=runtime_workspace)
    extension_control_snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    )
    with use_extension_control_snapshot(extension_control_snapshot):
        runtime_artifact = _hook_runtime_artifact(
            harness=args.harness,
            payload=payload,
            action_envelope=action_envelope,
            data_flow_signals=data_flow_signals,
            home_dir=context.home_dir,
            guard_home=context.guard_home,
            workspace=runtime_workspace,
        )
    result = run_native_claude_permission_request(
        args,
        config=config,
        output_stream=output_stream,
        payload=payload,
        runtime_artifact=runtime_artifact,
        runtime_workspace=runtime_workspace,
        store=store,
    )
    if result is not None:
        return result
    result = run_native_claude_permission_prompt_notification(
        args,
        output_stream=output_stream,
        payload=payload,
        store=store,
    )
    if result is not None:
        return result
    if _canonical_harness_name(args.harness) == "claude-code" and _hook_event_name(payload) == "Stop":
        discarded = _discard_claude_pending_permissions(store, payload)
        store.add_event(
            "claude/turn_stop",
            {
                "session_id": payload.get("session_id"),
                "discarded_pending_permissions": discarded,
            },
            _now(),
        )
        return 0
    if runtime_artifact is not None:
        return _run_native_artifact_hook_flow(
            args,
            action_envelope=action_envelope,
            config=config,
            context=context,
            data_flow_signals=data_flow_signals,
            payload=payload,
            runtime_artifact=runtime_artifact,
            runtime_workspace=runtime_workspace,
            store=store,
            managed_install=managed_install,
            output_stream=output_stream,
            workspace=runtime_workspace,
            native_edge_result=edge_result if isinstance(edge_result, Mapping) else None,
            native_edge_receipt=edge_receipt if isinstance(edge_receipt, Mapping) else None,
            native_recording_only=bool(edge.get("recording_only")) if isinstance(edge, Mapping) else False,
            _claimed_saved_allow_hash=_claimed_saved_allow_hash,
            _claimed_trusted_request_override=_claimed_trusted_request_override,
            _claimed_approval_request_id=_claimed_approval_request_id,
            _claim_saved_approval=_claim_saved_approval,
        )

    def revalidate_generic_after_claim(claimed_artifact_hash: str) -> int:
        fresh_config = overlay_synced_guard_policy(
            load_guard_config(context.guard_home, workspace=runtime_workspace),
            _synced_policy_payload(store),
        )
        fresh_action_envelope = _hook_action_envelope(
            harness=args.harness,
            payload=payload,
            home_dir=context.home_dir,
            workspace=runtime_workspace,
        )
        return run_native_generic_payload(
            args,
            action_envelope=fresh_action_envelope,
            config=fresh_config,
            home_dir=context.home_dir,
            output_stream=output_stream,
            payload=payload,
            runtime_artifact_checked=True,
            runtime_workspace=runtime_workspace,
            store=store,
            native_edge_result=edge_result if isinstance(edge_result, Mapping) else None,
            native_edge_receipt=edge_receipt if isinstance(edge_receipt, Mapping) else None,
            _claimed_saved_allow_hash=claimed_artifact_hash,
            _claim_saved_approval=False,
        )

    return run_native_generic_payload(
        args,
        action_envelope=action_envelope,
        config=config,
        home_dir=context.home_dir,
        output_stream=output_stream,
        payload=payload,
        runtime_artifact_checked=True,
        runtime_workspace=runtime_workspace,
        store=store,
        post_claim_revalidator=revalidate_generic_after_claim,
        native_edge_result=edge_result if isinstance(edge_result, Mapping) else None,
        native_edge_receipt=edge_receipt if isinstance(edge_receipt, Mapping) else None,
        _claimed_saved_allow_hash=_claimed_saved_allow_hash,
        _claim_saved_approval=_claim_saved_approval,
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
    )
    fresh_data_flow_signals = _runtime_action_data_flow_signals(fresh_action_envelope, workspace=runtime_workspace)
    fresh_snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    )
    with use_extension_control_snapshot(fresh_snapshot):
        fresh_runtime_artifact = _hook_runtime_artifact(
            harness=args.harness,
            payload=payload,
            action_envelope=fresh_action_envelope,
            data_flow_signals=fresh_data_flow_signals,
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
