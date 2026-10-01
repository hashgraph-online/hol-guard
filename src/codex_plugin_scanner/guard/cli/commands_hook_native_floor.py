"""Native PreToolUse floor helpers for runtime artifact hook evaluation."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from ..action_lattice import coerce_guard_action, most_restrictive_guard_action
from ..models import GuardAction, GuardArtifact
from ..native_mode import native_mode_requires_rust
from ..native_policy_snapshot_constants import NativePolicySnapshotError
from ..native_policy_snapshot_publisher import provision_native_verifier_key_for_store
from ..native_pretool import native_pre_tool_policy_floor
from ..runtime.actions import GuardActionEnvelope
from ..store import GuardStore
from .commands_hook_local_cli import local_cli_grant_action


def _runtime_package_raw_command(
    payload: Mapping[str, object],
    action_envelope: GuardActionEnvelope | None,
) -> str | None:
    for candidate in (
        payload.get("tool_input"),
        payload.get("arguments"),
        payload,
    ):
        if not isinstance(candidate, Mapping):
            continue
        for key in ("command", "cmd", "shell_command", "shellCommand"):
            value = candidate.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return action_envelope.command if action_envelope is not None else None


def native_pre_tool_floor_action(
    event_name: str,
    command: str | None,
    *,
    guard_home: Path,
    cwd: Path | None,
    home_dir: Path | None,
) -> GuardAction | None:
    if event_name != "PreToolUse" or command is None:
        return None
    return coerce_guard_action(
        native_pre_tool_policy_floor(
            command,
            guard_home=guard_home,
            cwd=cwd,
            home_dir=home_dir,
        )
    )


def _ensure_native_resident_verifier(
    store: GuardStore | None,
    guard_home: Path,
) -> None:
    """Provision the resident verifier key before a native floor request.

    Production hook entry provisions through the policy snapshot publisher at
    worker start.  A direct evaluator call must establish the same one-time
    prerequisite or the resident refuses to serve and the floor fails closed.
    Provisioning stays best-effort here: failure leaves the fail-closed floor
    intact instead of inventing a weaker native answer.
    """

    if store is None or not native_mode_requires_rust():
        return
    key_path = guard_home / "native-runtime" / "policy-verifier.key"
    try:
        if key_path.is_file():
            return
    except OSError:
        return
    try:
        provision_native_verifier_key_for_store(store)
    except (NativePolicySnapshotError, OSError, RuntimeError, TypeError, ValueError, AttributeError):
        return


def attach_native_pre_tool_floor(
    event_name: str,
    payload: Mapping[str, object],
    action_envelope: GuardActionEnvelope | None,
    current_action_inputs: list[GuardAction],
    *,
    guard_home: Path,
    cwd: Path | None,
    home_dir: Path,
    store: GuardStore | None = None,
) -> GuardAction | None:
    command = _runtime_package_raw_command(payload, action_envelope)
    if event_name == "PreToolUse" and command is not None:
        _ensure_native_resident_verifier(store, guard_home)
    floor = native_pre_tool_floor_action(
        event_name,
        command,
        guard_home=guard_home,
        cwd=cwd,
        home_dir=home_dir,
    )
    if floor is not None:
        current_action_inputs.append(floor)
    return floor


def apply_local_grant_then_native_floor(
    *,
    store: GuardStore,
    command: str | None,
    cwd: Path,
    home_dir: Path,
    current_policy_action: GuardAction,
    policy_action: GuardAction,
    approval_context_policy_action: GuardAction,
    grant_allowed: bool,
    native_floor: GuardAction | None,
) -> tuple[GuardAction, GuardAction, GuardAction]:
    granted = local_cli_grant_action(
        store=store,
        command=command,
        cwd=cwd,
        home_dir=home_dir,
        current_action=current_policy_action,
        grant_allowed=grant_allowed,
    )
    if granted != current_policy_action:
        current_policy_action = granted
        policy_action = granted
        approval_context_policy_action = granted
    if native_floor is None:
        return policy_action, current_policy_action, approval_context_policy_action
    # The floor already entered ``current_action_inputs``, so
    # ``policy_action`` and ``current_policy_action`` carry it whenever no
    # grant settled the review.  Re-flooring ``policy_action`` here would make
    # every saved approval or granted tool re-flag the identical request
    # forever, and re-flooring ``current_policy_action`` feeds that floor back
    # into approval-reuse evaluation which then clobbers the settled allow.
    # Only the approval-context action is re-floored: it binds the identity of
    # the review the floor demanded so saved approvals still match exactly.
    return (
        policy_action,
        current_policy_action,
        most_restrictive_guard_action(approval_context_policy_action, native_floor),
    )


def runtime_hook_scanner_setup(
    runtime_artifact: GuardArtifact,
    action_envelope: GuardActionEnvelope | None,
    runtime_workspace: Path | None,
    cisco_scanner: Callable[..., tuple[Any, ...]],
) -> tuple[list[str], dict[str, object], tuple[Any, ...]]:
    artifact_metadata = runtime_artifact.metadata if isinstance(runtime_artifact.metadata, dict) else {}
    raw_shell_cwds = artifact_metadata.get("shell_execution_effective_cwds")
    shell_context_incomplete = (
        bool(
            artifact_metadata.get("shell_execution_context_hash")
            or artifact_metadata.get("shell_execution_context_hashes")
        )
        and artifact_metadata.get("shell_execution_context_complete") is False
    )
    scanner_evidence = (
        cisco_scanner(
            action_envelope,
            runtime_workspace=runtime_workspace,
            raw_shell_cwds=raw_shell_cwds,
        )
        if action_envelope is not None and not shell_context_incomplete
        else ()
    )
    return [runtime_artifact.artifact_type], artifact_metadata, scanner_evidence
