"""Rebuild runtime hook authority after a claimed decision or approval wait."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import argparse
    from pathlib import Path

    from ..adapters.base import HarnessContext
    from ..store import GuardStore
    from .hook_exact_policy import HookExactCommandSource, HookPolicyClaim


def _fresh_runtime_artifact_evaluation(
    args: argparse.Namespace,
    *,
    context: HarnessContext,
    guard_home: Path,
    payload: dict[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
    claim_saved_approval: bool,
    exact_command_source: HookExactCommandSource | None = None,
    claimed_saved_allow_hash: HookPolicyClaim | None = None,
    claimed_trusted_request_override: bool = False,
    claimed_package_approval_consumed: bool = False,
    claimed_approval_request_id: str | None = None,
    trusted_request_override_hash: str | None = None,
    post_claim_revalidator=None,
):
    from ..config import load_guard_config, overlay_synced_guard_policy
    from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
    from ..runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot, use_extension_control_snapshot
    from .commands_hook_runtime_eval import _evaluate_runtime_artifact_hook
    from .commands_support_connect import _synced_policy_payload
    from .commands_support_hook_payload import _hook_action_envelope
    from .commands_support_runtime_artifacts import _hook_runtime_artifact
    from .commands_support_runtime_policy import _runtime_action_data_flow_signals

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
        _exact_command_source=exact_command_source,
        post_claim_revalidator=post_claim_revalidator if claimed_saved_allow_hash is None else None,
        _claimed_saved_allow_hash=claimed_saved_allow_hash,
        _claimed_trusted_request_override=claimed_trusted_request_override,
        _claimed_package_approval_consumed=claimed_package_approval_consumed,
        _claimed_approval_request_id=claimed_approval_request_id,
        _claim_saved_approval=claimed_saved_allow_hash is None and claim_saved_approval,
    )
