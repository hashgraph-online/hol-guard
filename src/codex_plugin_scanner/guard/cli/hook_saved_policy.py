"""Saved generic hook lookup with explicit exact-policy authority."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

from ..action_lattice import guard_action_severity
from ..models import GuardAction
from ..runtime.actions import command_text_from_tool_payload
from ..runtime.approval_context import approval_context_tokens_validation_reason, parse_approval_context_token
from ..runtime.approval_reuse import ApprovalReuseDecision, ApprovalReuseValidationFailure, evaluate_approval_reuse
from ..store import GuardStore
from .hook_exact_policy import HookExactCommandSource, authenticated_exact_policy_allow, hook_exact_command_digest


def _coalesce_string(*values: object) -> str:
    return next((value.strip() for value in values if isinstance(value, str) and value.strip()), "unknown-artifact")


def _optional_string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _generic_hook_memory_command(payload: Mapping[str, object]) -> str:
    command = command_text_from_tool_payload(
        payload.get("tool_name"),
        payload.get("tool_input", payload.get("arguments")),
    )
    return _coalesce_string(command, payload.get("command"), payload.get("tool_name"))


def _generic_hook_saved_decision(
    *,
    artifact_hash: str,
    artifact_id: str,
    artifact_name: str,
    harness: str,
    legacy_artifact_hash: str | None,
    payload: Mapping[str, object],
    publisher: str | None,
    runtime_workspace: Path | None,
    store: GuardStore,
    exact_command_source: HookExactCommandSource | None = None,
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    """Peek saved evidence, retaining legacy blocks without trusting legacy allows."""

    exact_digest = (
        exact_command_source.sha256 if exact_command_source is not None else hook_exact_command_digest(payload)
    )
    workspace = str(runtime_workspace) if runtime_workspace is not None else None
    from ..store import runtime_tool_action_exact_match_context, runtime_tool_action_policy_artifact_id

    memory_command = _generic_hook_memory_command(payload)
    runtime_exact_match_context = runtime_tool_action_exact_match_context(
        config_path=workspace,
        source_scope=_coalesce_string(payload.get("source_scope"), "project"),
        raw_command_text=memory_command,
        permission_mode=_optional_string(payload.get("permission_mode"))
        or _optional_string(payload.get("permissionMode")),
    )
    lookup = store.resolve_policy_decision_lookup_with_memory_pattern(
        harness,
        artifact_id,
        artifact_hash=artifact_hash,
        exact_command_sha256=exact_digest,
        workspace=workspace,
        publisher=publisher,
        runtime_exact_match_context=runtime_exact_match_context,
        memory_command=memory_command,
        memory_artifact_type=_coalesce_string(payload.get("artifact_type"), payload.get("tool_type")),
        memory_artifact_name=artifact_name,
        consume_one_shot=False,
    )
    selected_decision = lookup["decision"]
    ignored_integrity = lookup.get("ignored_local_integrity")
    policy_artifact_id = runtime_tool_action_policy_artifact_id(artifact_id)
    if policy_artifact_id is not None and policy_artifact_id != artifact_id:
        exact_lookup = store.resolve_policy_decision_lookup_with_memory_pattern(
            harness,
            policy_artifact_id,
            artifact_hash=artifact_hash,
            exact_command_sha256=exact_digest,
            workspace=workspace,
            publisher=publisher,
            runtime_exact_match_context=runtime_exact_match_context,
            memory_command=memory_command,
            memory_artifact_type=_coalesce_string(payload.get("artifact_type"), payload.get("tool_type")),
            memory_artifact_name=artifact_name,
            consume_one_shot=False,
        )
        exact_decision = exact_lookup["decision"]
        if ignored_integrity is None:
            ignored_integrity = exact_lookup.get("ignored_local_integrity")
        if exact_decision is not None and (
            selected_decision is None
            or guard_action_severity(exact_decision.get("action"), unknown_action="block")
            > guard_action_severity(selected_decision.get("action"), unknown_action="block")
        ):
            selected_decision = exact_decision
            ignored_integrity = exact_lookup.get("ignored_local_integrity")
    if legacy_artifact_hash is not None and legacy_artifact_hash != artifact_hash:
        legacy_lookup = store.resolve_policy_decision_lookup_with_memory_pattern(
            harness,
            artifact_id,
            artifact_hash=legacy_artifact_hash,
            exact_command_sha256=exact_digest,
            workspace=workspace,
            publisher=publisher,
            runtime_exact_match_context=runtime_exact_match_context,
            memory_command=memory_command,
            memory_artifact_type=_coalesce_string(payload.get("artifact_type"), payload.get("tool_type")),
            memory_artifact_name=artifact_name,
            consume_one_shot=False,
        )
        legacy_decision = legacy_lookup["decision"]
        if ignored_integrity is None:
            ignored_integrity = legacy_lookup.get("ignored_local_integrity")
        if legacy_decision is not None and (
            selected_decision is None
            or guard_action_severity(legacy_decision.get("action"), unknown_action="block")
            > guard_action_severity(selected_decision.get("action"), unknown_action="block")
        ):
            selected_decision = legacy_decision
            ignored_integrity = legacy_lookup.get("ignored_local_integrity")
    return selected_decision, ignored_integrity


def _generic_hook_approval_reuse(
    *,
    artifact_hash: str,
    artifact_id: str,
    current_action: GuardAction,
    decision: dict[str, object] | None,
    harness: str,
    ignored_integrity: dict[str, object] | None,
    publisher: str | None,
    runtime_workspace: Path | None,
    store: GuardStore,
    exact_command_digest: str | None = None,
) -> tuple[ApprovalReuseDecision, bool]:
    saved_action: object | None = decision.get("action") if decision is not None else None
    saved_present = decision is not None or ignored_integrity is not None
    validation_reason: ApprovalReuseValidationFailure | None = None
    if ignored_integrity is not None:
        if decision is None:
            saved_action = "require-reapproval"
        validation_reason = "approval_reuse_integrity_failure"
    elif (
        decision is not None
        and decision.get("action") == "allow"
        and not authenticated_exact_policy_allow(
            store,
            decision,
            exact_command_digest,
        )
    ):
        from ..store import _is_runtime_scoped_exact_match_key

        saved_artifact_hash = decision.get("artifact_hash")
        if not _is_runtime_scoped_exact_match_key(
            saved_artifact_hash if isinstance(saved_artifact_hash, str) else None
        ):
            validation_reason = cast(
                ApprovalReuseValidationFailure | None,
                approval_context_tokens_validation_reason(saved_artifact_hash, artifact_hash),
            )
    if not saved_present:
        diagnosed_reason = store.approval_reuse_validation_reason(
            harness,
            artifact_id,
            artifact_hash,
            str(runtime_workspace) if runtime_workspace is not None else None,
            publisher,
        )
        if diagnosed_reason is not None:
            saved_action = "allow"
            saved_present = True
            validation_reason = cast(ApprovalReuseValidationFailure, diagnosed_reason)
    durable_exact_approval = (
        validation_reason is None
        and decision is not None
        and decision.get("action") == "allow"
        and decision.get("source") == "approval-gate"
        and decision.get("scope") == "artifact"
        and decision.get("expires_at") is None
        and parse_approval_context_token(decision.get("artifact_hash")) is not None
    )
    reuse = evaluate_approval_reuse(
        current_action,
        saved_action,
        saved_decision_present=saved_present,
        validation_reason=validation_reason,
        durable_exact_approval=durable_exact_approval,
    )
    return reuse, saved_present
