"""PostToolUse presentation when the native edge cannot answer.

The pipeline still calls the resident edge. This module owns the mechanical
artifact resolution and approval flow that remain after that call.
"""

# ruff: noqa: F403, F405

from __future__ import annotations

from collections.abc import Mapping

from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..runtime.extension_control_runtime import (
    ExtensionControlRuntimeSnapshot,
    use_extension_control_snapshot,
)
from ._commands_shared import *
from .commands_hook_native_eval import evaluate_native_artifact_hook
from .commands_hook_native_finish import finalize_native_artifact_hook
from .commands_hook_native_review import review_native_artifact_hook
from .commands_hook_native_state import NativeArtifactHookState
from .commands_support_connect import _synced_policy_payload
from .commands_support_hook_payload import _hook_action_envelope
from .commands_support_runtime_artifacts import _hook_runtime_artifact
from .commands_support_runtime_policy import _runtime_action_data_flow_signals


def runtime_error_is_symlink_loop(exc: BaseException) -> bool:
    """Return whether pathlib reported a symlink loop.

    Linux ``Path.resolve`` raises ``RuntimeError`` with this text. Other
    runtime failures stay worker exceptions unless secret output must pause.
    """

    return "symlink loop" in str(exc).casefold()


def hook_runtime_artifact_for_store(
    store: GuardStore,
    *,
    harness: str,
    payload: dict[str, object],
    action_envelope,
    data_flow_signals,
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
):
    """Resolve one hook artifact under the current extension-control snapshot."""

    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    )
    with use_extension_control_snapshot(snapshot):
        return _hook_runtime_artifact(
            harness=harness,
            payload=payload,
            action_envelope=action_envelope,
            data_flow_signals=data_flow_signals,
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )


def post_tool_secret_block_without_native_edge(
    args: argparse.Namespace,
    *,
    action_envelope,
    config: GuardConfig,
    context: HarnessContext,
    managed_install,
    output_stream: TextIO | None,
    payload: dict[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
    recording_only: bool,
    _claimed_saved_allow_hash: str | None,
    _claimed_trusted_request_override: bool,
    _claimed_approval_request_id: str | None,
    _claim_saved_approval: bool,
) -> int | None:
    """Block credential-looking output when the native edge cannot answer.

    A missing PostToolUse edge is not permission to release secret-looking
    tool output. Clean output keeps the unavailable continuation. Watch mode
    stays non-executable.
    """

    if recording_only:
        return None
    data_flow_signals = _runtime_action_data_flow_signals(action_envelope, workspace=runtime_workspace)
    runtime_artifact = hook_runtime_artifact_for_store(
        store,
        harness=args.harness,
        payload=payload,
        action_envelope=action_envelope,
        data_flow_signals=data_flow_signals,
        home_dir=context.home_dir,
        guard_home=context.guard_home,
        workspace=runtime_workspace,
    )
    if runtime_artifact is None:
        return None
    return run_native_artifact_hook_flow(
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
        native_edge_result=None,
        native_edge_receipt=None,
        native_recording_only=False,
        _claimed_saved_allow_hash=_claimed_saved_allow_hash,
        _claimed_trusted_request_override=_claimed_trusted_request_override,
        _claimed_approval_request_id=_claimed_approval_request_id,
        _claim_saved_approval=_claim_saved_approval,
    )


def fresh_native_artifact_evaluation(
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
    fresh_data_flow_signals = _runtime_action_data_flow_signals(fresh_action_envelope, workspace=runtime_workspace)
    fresh_runtime_artifact = hook_runtime_artifact_for_store(
        store,
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


def run_native_artifact_hook_flow(
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
        return fresh_native_artifact_evaluation(
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
        fresh = fresh_native_artifact_evaluation(
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
