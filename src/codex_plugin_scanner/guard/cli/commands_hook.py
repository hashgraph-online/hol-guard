"""Guard CLI hook command entrypoint."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..runtime.extension_control_runtime import (
    ExtensionControlRuntimeSnapshot,
    use_extension_control_snapshot,
)

if TYPE_CHECKING:
    from ._commands_shared import _now, _require_guard_config, _require_guard_context, _require_guard_store
    from .commands_support_claude_approval import _persist_claude_guard_question_decision
    from .commands_support_connect import _synced_policy_payload
    from .commands_support_hook_payload import _hook_action_envelope, _load_hook_payload, _normalize_hook_payload
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


from ._commands_shared import *
from .commands_hook_claude import (
    _run_hook_claude_permission_prompt_notification,
    _run_hook_claude_permission_request,
)
from .commands_hook_compatibility import maybe_handle_cursor_post_tool, prepare_compatibility_hook_payload
from .commands_hook_copilot import (
    _run_hook_copilot_permission_request,
    _run_hook_copilot_pretool,
)
from .commands_hook_generic import _run_hook_generic_payload
from .commands_hook_native_authority import try_native_or_source_ref_hook
from .commands_hook_runtime_eval import _evaluate_runtime_artifact_hook
from .commands_hook_runtime_finish import _finalize_runtime_artifact_hook
from .commands_hook_runtime_review import _review_runtime_artifact_hook
from .commands_hook_runtime_state import RuntimeArtifactHookState
from .commands_parser_helpers import *
from .commands_support_workspace import _workspace_from_hook_payload


def _run_guard_hook_command(
    args: argparse.Namespace,
    *,
    guard_home: Path | None = None,
    workspace: Path | None = None,
    context: HarnessContext | None = None,
    store: GuardStore | None = None,
    config: GuardConfig | None = None,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
    _claim_saved_approval: bool = True,
    _claimed_saved_allow_hash: str | None = None,
    _claimed_trusted_request_override: bool = False,
    _claimed_approval_request_id: str | None = None,
    _native_minimum_action: str | None = None,
) -> int:
    if guard_home is None:
        raise RuntimeError("Guard home is required")
    context = _require_guard_context(context)
    store = _require_guard_store(store)
    runtime_harness = getattr(args, "runtime_harness", None)
    if isinstance(runtime_harness, str) and runtime_harness.strip():
        args.harness = runtime_harness.strip()
    else:
        args.harness = resolve_runtime_hook_harness(args.harness)
    payload = _load_hook_payload(
        getattr(args, "event_file", None),
        input_text=input_text,
        harness=args.harness,
        normalize=False,
    )
    # Auto/force sends the bounded, authenticated raw payload to Rust before
    # any harness adapter or generic semantic normalization can project it.
    # Explicit off/shadow returns here and continues through the compatibility
    # normalizers below.
    if _native_minimum_action not in {None, "review"}:
        raise RuntimeError("Unsupported native minimum action")
    raw_routed = None
    if _native_minimum_action is None:
        raw_routed = try_native_or_source_ref_hook(
            args,
            config=config,
            context=context,
            payload=payload,
            runtime_workspace=workspace,
            store=store,
            allow_compatibility=False,
        )
    if raw_routed is not None:
        return raw_routed
    # Explicit off/shadow compatibility reaches this point after native has
    # declined authority.  Auto/force already returned a typed fail-safe
    # result above, so no hook request loads config here.
    config = _require_guard_config(config)
    # Explicit off/shadow compatibility owns reference hydration only after
    # native routing has declined authority. Auto/force therefore sends the
    # bounded reference envelope to Rust without Python file I/O.
    from ..runtime.hook_payload_reference import hydrate_hook_payload_reference

    payload = hydrate_hook_payload_reference(payload)
    payload = _normalize_hook_payload(payload, harness=args.harness)
    payload = prepare_compatibility_hook_payload(payload, harness=args.harness)
    managed_install = _managed_install_for(store, args.harness)
    workspace_was_explicit = workspace is not None
    runtime_workspace = _workspace_from_hook_payload(payload, workspace)
    if runtime_workspace is None and args.harness == "copilot":
        with suppress(OSError):
            current_workspace = Path.cwd().resolve()
            if current_workspace.is_dir():
                runtime_workspace = current_workspace
    runtime_workspace, cursor_result = maybe_handle_cursor_post_tool(
        args=args,
        payload=payload,
        context=context,
        store=store,
        runtime_workspace=runtime_workspace,
    )
    if cursor_result is not None:
        return cursor_result
    if args.harness == "copilot":
        runtime_workspace = _resolve_copilot_workspace_root(runtime_workspace)
    routed = None
    if _native_minimum_action is None:
        routed = try_native_or_source_ref_hook(
            args,
            config=config,
            context=context,
            payload=payload,
            runtime_workspace=runtime_workspace,
            store=store,
        )
    if routed is not None:
        return routed
    action_envelope = _hook_action_envelope(
        harness=args.harness,
        payload=payload,
        home_dir=context.home_dir,
        workspace=runtime_workspace,
    )
    copilot_hook_stage = _copilot_hook_stage(payload) if args.harness == "copilot" else None
    copilot_runtime_tool_call = (
        _copilot_runtime_tool_call(
            payload=payload,
            home_dir=context.home_dir,
            workspace=runtime_workspace,
            config=config,
            preferred_workspace_config="ide" if workspace_was_explicit else "cli",
        )
        if args.harness == "copilot"
        else None
    )

    def fresh_copilot_tool_call_authority():
        fresh_config = overlay_synced_guard_policy(
            load_guard_config(guard_home, workspace=runtime_workspace),
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

    result = _run_hook_copilot_pretool(
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
    result = _run_hook_copilot_permission_request(
        args,
        action_envelope=action_envelope,
        config=config,
        context=context,
        copilot_permission_request=copilot_permission_request,
        guard_home=guard_home,
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
    result = _run_hook_claude_permission_request(
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
    result = _run_hook_claude_permission_prompt_notification(
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
    if _canonical_harness_name(args.harness) == "claude-code" and _persist_claude_guard_question_decision(
        store, payload
    ):
        return 0
    if runtime_artifact is not None:
        return _run_runtime_artifact_hook_flow(
            args,
            action_envelope=action_envelope,
            config=config,
            context=context,
            data_flow_signals=data_flow_signals,
            guard_home=guard_home,
            payload=payload,
            runtime_artifact=runtime_artifact,
            runtime_workspace=runtime_workspace,
            store=store,
            managed_install=managed_install,
            output_stream=output_stream,
            workspace=workspace,
            _claimed_saved_allow_hash=_claimed_saved_allow_hash,
            _claimed_trusted_request_override=_claimed_trusted_request_override,
            _claimed_approval_request_id=_claimed_approval_request_id,
            _claim_saved_approval=_claim_saved_approval,
        )

    def revalidate_generic_after_claim(claimed_artifact_hash: str) -> int:
        fresh_config = overlay_synced_guard_policy(
            load_guard_config(guard_home, workspace=runtime_workspace),
            _synced_policy_payload(store),
        )
        fresh_action_envelope = _hook_action_envelope(
            harness=args.harness,
            payload=payload,
            home_dir=context.home_dir,
            workspace=runtime_workspace,
        )
        return _run_hook_generic_payload(
            args,
            action_envelope=fresh_action_envelope,
            config=fresh_config,
            home_dir=context.home_dir,
            output_stream=output_stream,
            payload=payload,
            runtime_artifact_checked=True,
            runtime_workspace=runtime_workspace,
            store=store,
            _claimed_saved_allow_hash=claimed_artifact_hash,
            _claim_saved_approval=False,
        )

    return _run_hook_generic_payload(
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
        _claimed_saved_allow_hash=_claimed_saved_allow_hash,
        _claim_saved_approval=_claim_saved_approval,
    )


def _fresh_runtime_artifact_evaluation(
    args: argparse.Namespace,
    *,
    context: HarnessContext,
    guard_home: Path,
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
):
    fresh_config = overlay_synced_guard_policy(
        load_guard_config(guard_home, workspace=runtime_workspace),
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
    return _evaluate_runtime_artifact_hook(
        args,
        action_envelope=fresh_action_envelope,
        config=fresh_config,
        context=context,
        data_flow_signals=fresh_data_flow_signals,
        guard_home=guard_home,
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
    )


def _run_runtime_artifact_hook_flow(
    args: argparse.Namespace,
    *,
    action_envelope,
    config: GuardConfig,
    context: HarnessContext,
    data_flow_signals,
    guard_home: Path,
    managed_install,
    output_stream: TextIO | None,
    payload: dict[str, object],
    runtime_artifact,
    runtime_workspace: Path | None,
    store: GuardStore,
    workspace: Path | None,
    _claimed_saved_allow_hash: str | None,
    _claimed_trusted_request_override: bool,
    _claimed_approval_request_id: str | None,
    _claim_saved_approval: bool,
) -> int:
    def revalidate_runtime_after_claim(claimed_hash, trusted_override, approval_request_id, package_consumed):
        return _fresh_runtime_artifact_evaluation(
            args,
            context=context,
            guard_home=guard_home,
            payload=payload,
            runtime_workspace=runtime_workspace,
            store=store,
            claim_saved_approval=_claim_saved_approval,
            claimed_saved_allow_hash=claimed_hash,
            claimed_trusted_request_override=trusted_override,
            claimed_package_approval_consumed=package_consumed,
            claimed_approval_request_id=approval_request_id,
            post_claim_revalidator=revalidate_runtime_after_claim,
        )

    evaluated = _evaluate_runtime_artifact_hook(
        args,
        action_envelope=action_envelope,
        config=config,
        context=context,
        data_flow_signals=data_flow_signals,
        guard_home=guard_home,
        payload=payload,
        runtime_artifact=runtime_artifact,
        runtime_workspace=runtime_workspace,
        store=store,
        post_claim_revalidator=revalidate_runtime_after_claim,
        _claimed_saved_allow_hash=_claimed_saved_allow_hash,
        _claimed_trusted_request_override=_claimed_trusted_request_override,
        _claimed_approval_request_id=_claimed_approval_request_id,
        _claim_saved_approval=_claim_saved_approval,
    )
    if isinstance(evaluated, int):
        return evaluated
    result = _review_runtime_artifact_hook(
        evaluated,
        args,
        config=config,
        context=context,
        guard_home=guard_home,
        managed_install=managed_install,
        output_stream=output_stream,
        payload=payload,
        store=store,
        workspace=workspace,
    )
    if result is not None:
        return result

    def revalidate_runtime_after_wait() -> RuntimeArtifactHookState | None:
        fresh = _fresh_runtime_artifact_evaluation(
            args,
            context=context,
            guard_home=guard_home,
            payload=payload,
            runtime_workspace=runtime_workspace,
            store=store,
            claim_saved_approval=_claim_saved_approval,
            trusted_request_override_hash=evaluated.runtime_artifact_hash,
        )
        return fresh if isinstance(fresh, RuntimeArtifactHookState) else None

    return _finalize_runtime_artifact_hook(
        evaluated,
        args,
        config=config,
        output_stream=output_stream,
        payload=payload,
        store=store,
        post_wait_revalidator=revalidate_runtime_after_wait,
    )


__all__ = [
    "_run_guard_hook_command",
]
